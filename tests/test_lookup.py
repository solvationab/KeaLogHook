#!/usr/bin/env python3
import contextlib
import gzip
import io
import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ip_audit_lookup


def record(event, timestamp, ip, client, expires=None, **extra):
    value = {
        "event": event,
        "timestamp": timestamp,
        "ip-address": ip,
        "address-family": "IPv6" if ":" in ip else "IPv4",
        "lease-type": extra.pop("lease-type", ""),
        "client-id": client,
        "hw-address": "aa:bb:cc:dd:ee:ff",
    }
    if expires:
        value["lease-expires"] = expires
    value.update(extra)
    return value


class LookupTests(unittest.TestCase):
    def test_cli_reports_lease_and_no_match_status(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            event = record(
                "lease-assign", "2025-01-01T00:00:00.123Z", "192.0.2.10", "client-a",
                "2025-01-01T01:00:00Z")
            base.write_text(json.dumps(event) + "\n", encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.main([
                    "192.0.2.10", "2025-01-01T00:30:00Z", str(base)])
            self.assertEqual(0, status)
            self.assertIn("2025-01-01T00:00:00.123000Z", output.getvalue())
            self.assertIn("client-id=client-a", output.getvalue())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.main([
                    "192.0.2.10", "2025-01-01T01:00:00Z", str(base)])
            self.assertEqual(1, status)
            self.assertIn("no matching lease", output.getvalue())

    def test_reads_numbered_gzip_rotation_and_ignores_stale_release(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            rotated = Path(str(base) + ".1.gz")
            with gzip.open(rotated, "wt", encoding="utf-8") as output:
                output.write(json.dumps(record(
                    "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                    "2025-01-01T10:00:00Z")) + "\n")
            records = [
                record("lease-renew", "2025-01-01T01:00:00Z", "192.0.2.10", "client-a",
                       "2025-01-01T20:00:00Z"),
                record("lease-assign", "2025-01-01T02:00:00Z", "192.0.2.10", "client-b",
                       "2025-01-01T12:00:00Z"),
                record("lease-release", "2025-01-01T03:00:00Z", "192.0.2.10", "client-a",
                       "2025-01-01T12:00:00Z"),
            ]
            base.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

            address = ipaddress.ip_address("192.0.2.10")
            events = ip_audit_lookup.load_events([str(base)], address)
            intervals = ip_audit_lookup.reconstruct_intervals(events)
            matches = [interval for interval in intervals
                       if interval.start <= ip_audit_lookup.parse_timestamp("2025-01-01T03:30:00Z")
                       and (interval.end is None or
                            ip_audit_lookup.parse_timestamp("2025-01-01T03:30:00Z") < interval.end)]

            self.assertEqual(2, len(intervals))
            self.assertEqual(1, len(matches))
            self.assertEqual(
                ip_audit_lookup.parse_timestamp("2025-01-01T00:00:00Z"), intervals[0].start)
            self.assertEqual("client-b", matches[0].record["client-id"])
            self.assertEqual("reassigned", intervals[0].ended_by)

    def test_ipv6_delegated_prefix_matches_address_until_expiry(self):
        network = ip_audit_lookup.record_network({
            "ip-address": "2001:db8:1::",
            "prefix-length": 64,
        })
        self.assertIn(ipaddress.ip_address("2001:db8:1::1234"), network)
        interval = ip_audit_lookup.LeaseInterval(
            network,
            ip_audit_lookup.parse_timestamp("2025-01-01T00:00:00Z"),
            ip_audit_lookup.parse_timestamp("2025-01-01T01:00:00Z"),
            {"duid": "00:01"},
        )
        query_time = ip_audit_lookup.parse_timestamp("2025-01-01T01:00:00Z")
        self.assertFalse(interval.start <= query_time < interval.end)

    def test_rejects_timezone_naive_timestamps(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            ip_audit_lookup.parse_timestamp("2025-01-01T00:00:00")


if __name__ == "__main__":
    unittest.main()