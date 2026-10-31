#!/usr/bin/env python3
"""Verifies the audit log written during the relay_client.py run."""

import argparse
import json
import sys
import time

EXPECTED_EVENTS = ("lease-assign", "lease-renew", "lease-delete", "lease-release")


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--giaddr", required=True)
    parser.add_argument("--circuit-id", required=True)
    parser.add_argument("--remote-id", required=True)
    parser.add_argument("--pop", required=True)
    parser.add_argument("--site", required=True)
    args = parser.parse_args()

    expected = {
        "ip-address": args.ip,
        "hw-address": args.mac,
        "giaddr": args.giaddr,
        "circuit-id": args.circuit_id,
        "remote-id": args.remote_id,
        "vendor-class": "746573742d76656e646f72",
        "vendor-class-text": "test-vendor",
        "user-class": "05636c617373",
        "relay-flags": "01",
        "relay-vendor-specific": "00000123aabb",
        "pop": args.pop,
        "site": args.site,
    }

    # The release is not answered, so the last record may arrive after the client exits.
    deadline = time.time() + 10
    while True:
        records = load(args.log)
        seen = {r.get("event") for r in records}
        if all(e in seen for e in EXPECTED_EVENTS) or time.time() > deadline:
            break
        time.sleep(0.2)

    errors = []
    for event in EXPECTED_EVENTS:
        matching = [r for r in records if r.get("event") == event]
        if not matching:
            errors.append("no %s record" % event)
            continue
        for key, value in expected.items():
            if matching[0].get(key) != value:
                errors.append("%s: %s is %r, expected %r" % (event, key, matching[0].get(key), value))

    if errors:
        print("audit log check failed:", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        print("records:", file=sys.stderr)
        for r in records:
            print("  " + json.dumps(r), file=sys.stderr)
        return 1

    print("audit log OK (%d records)" % len(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
