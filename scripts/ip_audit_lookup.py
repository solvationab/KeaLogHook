#!/usr/bin/env python3
"""Look up the lease history for an address in Kea IP audit logs."""

import argparse
import csv
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
SUBSCRIBER_IDENTIFIERS = (
    "circuit-id", "remote-id", "subscriber-id", "hw-address", "client-id", "duid")


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


def load_events(specifications, query_address=None):
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
                if network is None:
                    continue
                if query_address is not None and (
                        query_address.version != network.version or query_address not in network):
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
    for field in ("client-id", "hw-address", "duid", "hostname", "server", "circuit-id",
                  "remote-id", "subscriber-id"):
        value = record.get(field)
        if value:
            details.append("%s=%s" % (field, value))
    return " ".join(details) if details else "identity unavailable"


def add_output_format_options(parser):
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", dest="output_format", action="store_const", const="json",
                         help="write machine-readable JSON")
    formats.add_argument("--table", dest="output_format", action="store_const", const="table",
                         help="write tab-separated tables")
    parser.set_defaults(output_format="text")


def write_table(headers, rows):
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)


def list_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ip-audit-list",
        description="List unexpired allocations inferred from JSON audit logs.")
    parser.add_argument("logs", nargs="+", help="log file, base log path, or quoted glob pattern")
    parser.add_argument("--at", help="timezone-aware ISO 8601 snapshot time (default: now)")
    add_output_format_options(parser)
    args = parser.parse_args(argv)

    try:
        snapshot_time = parse_timestamp(args.at) if args.at else datetime.now(timezone.utc)
        events = [event for event in load_events(args.logs) if event.timestamp <= snapshot_time]
        intervals = reconstruct_intervals(events)
    except (OSError, ValueError, EOFError, gzip.BadGzipFile) as error:
        print("ip-audit-list: %s" % error, file=sys.stderr)
        return 2

    unknown_expiry = sum(interval.end is None for interval in intervals)
    if unknown_expiry:
        print("ip-audit-list: omitted %d allocation(s) with unknown expiry" % unknown_expiry,
              file=sys.stderr)
    current = [interval for interval in intervals
               if interval.end is not None and interval.start <= snapshot_time < interval.end]
    current.sort(key=lambda interval: (
        interval.network.version, int(interval.network.network_address),
        interval.network.prefixlen, interval.record.get("lease-type", "")))
    leases = [{
        "network": str(interval.network),
        "start": format_time(interval.start),
        "end": format_time(interval.end),
        "record": interval.record,
    } for interval in current]
    result = {"as-of": format_time(snapshot_time), "source": "audit-logs",
              "count": len(leases), "leases": leases}
    if args.output_format == "json":
        json.dump(result, sys.stdout, indent=2)
        print()
    elif args.output_format == "table":
        print("As of %s" % result["as-of"])
        write_table(
            ["network", "start", "end", "address-family", "lease-type", "client"],
            [[lease["network"], lease["start"], lease["end"],
              lease["record"].get("address-family", ""),
              lease["record"].get("lease-type", ""), describe_client(lease["record"])]
             for lease in leases])
    else:
        print("As of %s" % result["as-of"])
        print("Active allocations: %d" % result["count"])
        for lease in leases:
            print("  %s [%s, %s) %s" % (
                lease["network"], lease["start"], lease["end"],
                describe_client(lease["record"])))
    return 0


def interval_for_event(event, intervals):
    network = record_network(event.record)
    if network is None:
        return None
    key = lease_key(event.record, network)
    matches = [interval for interval in intervals
               if lease_key(interval.record, interval.network) == key
               and interval.start <= event.timestamp
               and (interval.end is None or event.timestamp <= interval.end)
               and same_client(interval.record, event.record)]
    return max(matches, key=lambda interval: interval.start) if matches else None


def subscriber_main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ip-audit-subscriber",
        description="Search exact subscriber identifiers across audit logs and lease history.")
    parser.add_argument("--type", dest="identifier_type", required=True,
                        choices=SUBSCRIBER_IDENTIFIERS,
                        help="record field used as the exact-match identifier")
    parser.add_argument("--value", required=True,
                        help="case-sensitive identifier value exactly as logged")
    parser.add_argument("--from", dest="range_start", required=True,
                        help="inclusive timezone-aware ISO 8601 start")
    parser.add_argument("--to", dest="range_end", required=True,
                        help="exclusive timezone-aware ISO 8601 end")
    parser.add_argument("logs", nargs="+", help="log file, base log path, or quoted glob pattern")
    add_output_format_options(parser)
    args = parser.parse_args(argv)

    try:
        if not args.value:
            raise ValueError("identifier value must not be empty")
        range_start = parse_timestamp(args.range_start)
        range_end = parse_timestamp(args.range_end)
        if range_start >= range_end:
            raise ValueError("range start must be earlier than range end")

        events = load_events(args.logs)
        intervals = reconstruct_intervals(events)
        matches = [event for event in events
                   if range_start <= event.timestamp < range_end
                   and event.record.get(args.identifier_type) == args.value]
        results = []
        for event in matches:
            interval = interval_for_event(event, intervals)
            results.append({
                "timestamp": format_time(event.timestamp),
                "event": event.record.get("event", ""),
                "ip-address": event.record.get("ip-address", ""),
                "address-family": event.record.get("address-family", ""),
                "lease-type": event.record.get("lease-type", ""),
                "lease-start": format_time(interval.start) if interval else "",
                "lease-end": format_time(interval.end) if interval else "",
                "server": event.record.get("server", ""),
                "source": event.source,
                "line": event.line,
                "record": event.record,
            })
    except (OSError, ValueError, EOFError, gzip.BadGzipFile) as error:
        print("ip-audit-subscriber: %s" % error, file=sys.stderr)
        return 2

    result = {
        "identifier": {"type": args.identifier_type, "value": args.value,
                       "match": "exact", "case-sensitive": True},
        "range": {"from": format_time(range_start), "to": format_time(range_end),
                  "semantics": "[from, to)"},
        "count": len(results),
        "events": results,
    }
    if args.output_format == "json":
        json.dump(result, sys.stdout, indent=2)
        print()
    elif args.output_format == "table":
        write_table(
            ["timestamp", "event", "ip-address", "lease-start", "lease-end",
             "address-family", "lease-type", "server", "source", "line"],
            [[row[column] for column in
              ("timestamp", "event", "ip-address", "lease-start", "lease-end",
               "address-family", "lease-type", "server", "source", "line")]
             for row in results])
    else:
        print("Identifier: %s=%s (exact, case-sensitive)" %
              (args.identifier_type, args.value))
        print("Range: [%s, %s)" % (result["range"]["from"], result["range"]["to"]))
        print("Matching events: %d" % len(results))
        for row in results:
            print("  %s %-13s ip=%s lease=[%s, %s) server=%s (%s:%d)" % (
                row["timestamp"], row["event"], row["ip-address"],
                row["lease-start"] or "unknown", row["lease-end"] or "unknown",
                row["server"] or "unknown", row["source"], row["line"]))
    return 0 if results else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reconstruct lease history from JSON audit logs and numbered rotations.")
    parser.add_argument("ip", help="IPv4 or IPv6 address to look up")
    parser.add_argument("timestamp", help="timezone-aware ISO 8601 query time")
    parser.add_argument("logs", nargs="+", help="log file, base log path, or quoted glob pattern")
    add_output_format_options(parser)
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
    if args.output_format == "json":
        result = {
            "query": {"ip": str(query_address), "timestamp": format_time(query_time)},
            "matches": [{
                "network": str(interval.network),
                "start": format_time(interval.start),
                "end": format_time(interval.end),
                "record": interval.record,
            } for interval in matches],
            "events": [{
                "timestamp": format_time(event.timestamp),
                "event": event.record.get("event", ""),
                "ip-address": event.record.get("ip-address", ""),
                "client": describe_client(event.record),
                "source": event.source,
                "line": event.line,
                "record": event.record,
            } for event in events],
        }
        json.dump(result, sys.stdout, indent=2)
        print()
        return 0 if matches else 1

    if args.output_format == "table":
        print("Lease at query time")
        if matches:
            write_table(["network", "start", "end", "client"], [
                [str(interval.network), format_time(interval.start), format_time(interval.end),
                 describe_client(interval.record)] for interval in matches])
        else:
            print("No matching lease")
        print("Timeline")
        if events:
            write_table(["timestamp", "event", "address", "client", "source", "line"], [
                [format_time(event.timestamp), event.record.get("event", ""),
                 event.record.get("ip-address", ""), describe_client(event.record),
                 event.source, event.line] for event in events])
        else:
            print("No matching audit events")
        return 0 if matches else 1

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
    command_name = os.path.basename(sys.argv[0])
    if command_name == "ip-audit-list":
        command = list_main
    elif command_name == "ip-audit-subscriber":
        command = subscriber_main
    else:
        command = main
    sys.exit(command())