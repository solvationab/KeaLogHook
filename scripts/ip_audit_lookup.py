#!/usr/bin/env python3
"""Look up the lease history for an address in Kea IP audit logs."""

import argparse
import gzip
import glob
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone


OPEN_EVENTS = {"lease-assign", "lease-renew"}
CLOSE_EVENTS = {"lease-delete", "lease-release", "lease-decline", "lease-expire"}


@dataclass
class Event:
    timestamp: datetime
    record: dict
    source: str
    line: int


@dataclass
class LeaseInterval:
    network: object
    start: datetime
    end: object
    record: dict
    ended_by: str = ""


def parse_timestamp(value):
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty ISO 8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def record_network(record):
    value = record.get("ip-address")
    if not isinstance(value, str) or not value:
        return None
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        address = ipaddress.ip_address(value)
        prefix = record.get("prefix-length")
        if isinstance(prefix, int) and not isinstance(prefix, bool):
            return ipaddress.ip_network("%s/%d" % (address, prefix), strict=False)
        return ipaddress.ip_network("%s/%d" % (address, address.max_prefixlen), strict=False)
    except ValueError:
        return None


def expand_log_paths(specifications):
    paths = []
    for specification in specifications:
        if glob.has_magic(specification):
            matches = glob.glob(specification)
        else:
            matches = [specification] if os.path.isfile(specification) else []
            for candidate in glob.glob(specification + ".*"):
                suffix = candidate[len(specification) + 1:]
                if suffix.endswith(".gz"):
                    suffix = suffix[:-3]
                if re.fullmatch(r"[0-9]+", suffix):
                    matches.append(candidate)
        matches = sorted(path for path in matches if os.path.isfile(path))
        if not matches:
            raise OSError("no log file found for '%s'" % specification)
        paths.extend(matches)

    unique = {}
    for path in paths:
        unique[os.path.realpath(path)] = path
    return sorted(unique.values())


def load_events(specifications, query_address):
    events = []
    for path in expand_log_paths(specifications):
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError("%s:%d: invalid JSON: %s" %
                                     (path, line_number, error)) from error
                if not isinstance(record, dict):
                    raise ValueError("%s:%d: expected a JSON object" % (path, line_number))

                network = record_network(record)
                if network is None or query_address.version != network.version:
                    continue
                if query_address not in network:
                    continue
                event_name = record.get("event")
                if event_name not in OPEN_EVENTS and event_name not in CLOSE_EVENTS:
                    continue
                try:
                    timestamp = parse_timestamp(record.get("timestamp"))
                except ValueError as error:
                    raise ValueError("%s:%d: %s" % (path, line_number, error)) from error
                events.append(Event(timestamp, record, path, line_number))

    events.sort(key=lambda event: (
        event.timestamp,
        1 if event.record.get("event") in CLOSE_EVENTS else 0,
        event.source,
        event.line,
    ))
    return events


def lease_key(record, network):
    return (str(network), record.get("address-family", ""), record.get("lease-type", ""))


def client_identity(record):
    identity = tuple(record.get(field, "") or ""
                     for field in ("client-id", "hw-address", "duid"))
    return identity if any(identity) else None


def same_client(left, right):
    left_identity = client_identity(left)
    right_identity = client_identity(right)
    return left_identity is None or right_identity is None or left_identity == right_identity


def expiry_for(record):
    value = record.get("lease-expires")
    return parse_timestamp(value) if value else None


def close_interval(interval, timestamp, event_name):
    if interval.end is None or timestamp < interval.end:
        interval.end = timestamp
        interval.ended_by = event_name
    elif not interval.ended_by:
        interval.ended_by = "lease-expires"


def reconstruct_intervals(events):
    active = {}
    intervals = []
    for event in events:
        record = event.record
        network = record_network(record)
        key = lease_key(record, network)
        current = active.get(key)

        if record["event"] in OPEN_EVENTS:
            expiry = expiry_for(record)
            if current:
                if current.end is not None and event.timestamp >= current.end:
                    if not current.ended_by:
                        current.ended_by = "lease-expires"
                    del active[key]
                    current = None
                elif same_client(current.record, record):
                    if expiry is not None and (current.end is None or expiry > current.end):
                        current.end = expiry
                    current.record = record
                    continue
                else:
                    close_interval(current, event.timestamp, "reassigned")
                    del active[key]

            interval = LeaseInterval(network, event.timestamp, expiry, record)
            intervals.append(interval)
            active[key] = interval
            continue

        if current and same_client(current.record, record):
            close_interval(current, event.timestamp, record["event"])
            del active[key]

    intervals.sort(key=lambda interval: (interval.start, str(interval.network)))
    return intervals


def format_time(value):
    if value is None:
        return "unknown"
    return value.isoformat().replace("+00:00", "Z")


def describe_client(record):
    details = []
    for field in ("client-id", "hw-address", "duid", "hostname", "server", "circuit-id", "remote-id"):
        value = record.get(field)
        if value:
            details.append("%s=%s" % (field, value))
    return " ".join(details) if details else "identity unavailable"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reconstruct lease history from JSON audit logs and numbered rotations.")
    parser.add_argument("ip", help="IPv4 or IPv6 address to look up")
    parser.add_argument("timestamp", help="timezone-aware ISO 8601 query time")
    parser.add_argument("logs", nargs="+", help="log file, base log path, or quoted glob pattern")
    args = parser.parse_args(argv)

    try:
        query_address = ipaddress.ip_address(args.ip)
        query_time = parse_timestamp(args.timestamp)
        events = load_events(args.logs, query_address)
        intervals = reconstruct_intervals(events)
    except (OSError, ValueError, EOFError, gzip.BadGzipFile) as error:
        print("ip-audit-lookup: %s" % error, file=sys.stderr)
        return 2

    matches = [interval for interval in intervals
               if interval.start <= query_time and
               (interval.end is None or query_time < interval.end)]
    print("Query: %s at %s" % (query_address, format_time(query_time)))
    if matches:
        print("Lease at query time:")
        for interval in matches:
            print("  %s [%s, %s) %s" % (
                interval.network, format_time(interval.start), format_time(interval.end),
                describe_client(interval.record)))
    else:
        print("Lease at query time: no matching lease")

    print("Timeline:")
    if not events:
        print("  no matching audit events")
    for event in events:
        print("  %s %-13s %s (%s:%d)" % (
            format_time(event.timestamp), event.record.get("event", ""),
            describe_client(event.record), event.source, event.line))
    return 0 if matches else 1


if __name__ == "__main__":
    sys.exit(main())