#!/usr/bin/env python3
import contextlib
import gzip
import io
import ipaddress
import json
import shutil
import subprocess
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

    def test_lookup_json_and_table_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            base.write_text(json.dumps(record(
                "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                "2025-01-01T01:00:00Z")) + "\n", encoding="utf-8")
            arguments = ["192.0.2.10", "2025-01-01T00:30:00Z", str(base)]

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.main(arguments + ["--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(0, status)
            self.assertEqual("192.0.2.10", result["query"]["ip"])
            self.assertEqual("192.0.2.10/32", result["matches"][0]["network"])
            self.assertEqual("lease-assign", result["events"][0]["event"])

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.main(arguments + ["--table"])
            self.assertEqual(0, status)
            self.assertIn("network\tstart\tend\tclient", output.getvalue())
            self.assertIn("timestamp\tevent\taddress\tclient\tsource\tline", output.getvalue())
            self.assertIn("lease-assign", output.getvalue())

    def test_output_format_options_are_mutually_exclusive(self):
        commands = (
            (ip_audit_lookup.main,
             ["192.0.2.10", "2025-01-01T00:30:00Z", "audit.log", "--json", "--table"]),
            (ip_audit_lookup.list_main, ["audit.log", "--json", "--table"]),
            (ip_audit_lookup.subscriber_main, ["--type", "duid", "--value", "x",
                                               "--from", "2025-01-01T00:00:00Z",
                                               "--to", "2025-01-02T00:00:00Z", "audit.log",
                                               "--json", "--table"]),
        )
        for command, arguments in commands:
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
                command(arguments)
            self.assertEqual(2, raised.exception.code)
            self.assertIn("not allowed with argument", errors.getvalue())

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

    def test_subscriber_search_is_exact_and_includes_interval_history(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            rotated = Path(str(base) + ".1.gz")
            with gzip.open(rotated, "wt", encoding="utf-8") as output:
                output.write(json.dumps(record(
                    "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                    "2025-01-01T08:00:00Z", **{"circuit-id": "port-1"})) + "\n")
            records = [
                record("lease-renew", "2025-01-01T01:00:00Z", "192.0.2.10", "client-a",
                       "2025-01-01T09:00:00Z", **{"circuit-id": "port-1"}),
                record("lease-assign", "2025-01-01T02:00:00Z", "192.0.2.11", "client-a",
                       "2025-01-01T10:00:00Z", **{"circuit-id": "port-1"}),
                record("lease-assign", "2025-01-01T02:00:00Z", "192.0.2.12", "client-b",
                       "2025-01-01T10:00:00Z", **{"circuit-id": "Port-1"}),
                record("lease-release", "2025-01-01T03:00:00Z", "192.0.2.10", "client-a",
                       **{"circuit-id": "port-1"}),
                record("lease-assign", "2025-01-01T04:00:00Z", "192.0.2.13", "client-a",
                       "2025-01-01T10:00:00Z", **{"circuit-id": "port-1"}),
            ]
            base.write_text("".join(json.dumps(item) + "\n" for item in records),
                            encoding="utf-8")
            arguments = ["--type", "circuit-id", "--value", "port-1",
                         "--from", "2025-01-01T00:00:00Z", "--to", "2025-01-01T04:00:00Z",
                         str(base)]

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.subscriber_main(arguments + ["--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(0, status)
            self.assertEqual(4, result["count"])
            self.assertEqual("exact", result["identifier"]["match"])
            self.assertEqual("[from, to)", result["range"]["semantics"])
            self.assertEqual({"192.0.2.10", "192.0.2.11"},
                             {event["ip-address"] for event in result["events"]})
            self.assertEqual("2025-01-01T00:00:00Z", result["events"][0]["lease-start"])
            self.assertNotIn("192.0.2.12", output.getvalue())
            self.assertNotIn("192.0.2.13", output.getvalue())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.subscriber_main(arguments + ["--table"])
            self.assertEqual(0, status)
            self.assertIn("timestamp\tevent\tip-address\tlease-start", output.getvalue())
            self.assertNotIn("circuit-id", output.getvalue())

    def test_subscriber_search_validates_range_and_identifier(self):
        base_arguments = ["--type", "hw-address", "--value", "aa:bb",
                          "--from", "2025-01-02T00:00:00Z",
                          "--to", "2025-01-01T00:00:00Z", "missing.log"]
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = ip_audit_lookup.subscriber_main(base_arguments)
        self.assertEqual(2, status)
        self.assertIn("range start must be earlier", errors.getvalue())

    def test_subscriber_command_alias_uses_readable_default(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "ip-audit-subscriber"
            shutil.copyfile(ip_audit_lookup.__file__, command)
            base = Path(directory) / "audit.log"
            base.write_text(json.dumps(record(
                "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                "2025-01-01T01:00:00Z", **{"remote-id": "001122"})) + "\n",
                encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(command), "--type", "remote-id", "--value", "001122",
                "--from", "2025-01-01T00:00:00Z", "--to", "2025-01-02T00:00:00Z",
                str(base)], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Matching events: 1", result.stdout)
            self.assertIn("ip=192.0.2.10", result.stdout)

    def test_check_scans_rotations_and_separates_errors_from_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            rotated = Path(str(base) + ".1.gz")
            with gzip.open(rotated, "wt", encoding="utf-8") as output:
                output.write(json.dumps(record(
                    "lease-assign", "2024-12-31T23:00:00Z", "192.0.2.1", "rotated",
                    "2025-01-01T00:00:00Z", **{"schema-version": "1.0.0"})) + "\n")

            lines = [
                json.dumps(record(
                    "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                    "2025-01-01T02:00:00Z", **{"schema-version": "1.0.0"})),
                "{not-json",
                json.dumps(record(
                    "lease-renew", "not-a-time", "192.0.2.10", "client-a",
                    "2025-01-01T02:00:00Z", **{"schema-version": "1.0.0"})),
                json.dumps(record(
                    "lease-assign", "2025-01-01T01:00:00Z", "192.0.2.11", "client-b",
                    "2025-01-01T03:00:00Z", **{"schema-version": "9.0.0"})),
                json.dumps({"timestamp": "2025-01-01T02:00:00Z"}),
                json.dumps(record(
                    "lease-expire", "2025-01-01T04:00:00Z", "192.0.2.12", "client-c",
                    "invalid-expiry", **{"schema-version": "1.0.0"})),
            ]
            base.write_text("\n".join(lines) + "\n", encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.check_main([str(base), "--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(1, status)
            self.assertEqual(2, result["totals"]["files"])
            self.assertEqual(7, result["totals"]["records-scanned"])
            self.assertEqual(4, result["totals"]["errors"])
            self.assertGreaterEqual(result["totals"]["warnings"], 3)
            base_summary = next(item for item in result["files"] if item["file"] == str(base))
            self.assertEqual("2025-01-01T00:00:00Z", base_summary["first-timestamp"])
            self.assertEqual("2025-01-01T04:00:00Z", base_summary["last-timestamp"])
            self.assertEqual(1, base_summary["events"]["<missing>"])
            codes = {item["code"] for item in result["diagnostics"]}
            self.assertTrue({"malformed-json", "invalid-timestamp", "unsupported-schema-version",
                             "missing-reconstruction-fields", "invalid-lease-expires",
                             "missing-schema-version"}.issubset(codes))

    def test_check_output_formats_and_warning_only_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            base.write_text(json.dumps({
                "schema-version": "1.0.0",
                "timestamp": "2025-01-01T00:00:00Z",
            }) + "\n", encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.check_main([str(base)])
            self.assertEqual(0, status)
            self.assertIn("Errors: 0; warnings:", output.getvalue())
            self.assertIn("missing-reconstruction-fields", output.getvalue())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.check_main([str(base), "--table"])
            self.assertEqual(0, status)
            self.assertIn("file\trecords-scanned\tfirst-timestamp", output.getvalue())
            self.assertIn("severity\tfile\tline\tcode\tmessage", output.getvalue())

            command = Path(directory) / "ip-audit-check"
            shutil.copyfile(ip_audit_lookup.__file__, command)
            result = subprocess.run([sys.executable, str(command), "--json", str(base)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(0, json.loads(result.stdout)["totals"]["errors"])

    def test_check_time_coverage_orders_subsecond_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            records = [
                record("lease-assign", "2025-01-01T00:00:00.900Z", "192.0.2.10", "client-a",
                       "2025-01-01T01:00:00Z", **{"schema-version": "1.0.0"}),
                record("lease-renew", "2025-01-01T00:00:00.100Z", "192.0.2.10", "client-a",
                       "2025-01-01T02:00:00Z", **{"schema-version": "1.0.0"}),
            ]
            base.write_text("".join(json.dumps(item) + "\n" for item in records),
                            encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.check_main([str(base), "--json"])
            summary = json.loads(output.getvalue())["files"][0]
            self.assertEqual(0, status)
            self.assertEqual("2025-01-01T00:00:00.100000Z", summary["first-timestamp"])
            self.assertEqual("2025-01-01T00:00:00.900000Z", summary["last-timestamp"])

    def test_check_rejects_missing_logs_and_caps_diagnostic_details(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            status = ip_audit_lookup.check_main(["/path/that/does/not/exist"])
        self.assertEqual(2, status)
        self.assertIn("ip-audit-check:", errors.getvalue())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            base.write_text("{bad-json}\n" * 105, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = ip_audit_lookup.check_main([str(base), "--json"])
            result = json.loads(output.getvalue())
            self.assertEqual(1, status)
            self.assertEqual(105, result["totals"]["errors"])
            self.assertEqual(100, len(result["diagnostics"]))
            self.assertEqual(5, result["diagnostics-omitted"])

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

    def test_list_current_allocations_with_all_record_data(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            records = [
                record("lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "client-a",
                       "2025-01-01T01:00:00Z"),
                record("lease-renew", "2025-01-01T00:30:00Z", "192.0.2.10", "client-a",
                       "2025-01-01T03:00:00Z", **{"circuit-id-text": "port-1",
                                                "remote-id-text": r"\x00switch"}),
                record("lease-assign", "2025-01-01T00:00:00Z", "192.0.2.11", "expired",
                       "2025-01-01T01:00:00Z"),
                record("lease-assign", "2025-01-01T00:00:00Z", "192.0.2.12", "released",
                       "2025-01-01T03:00:00Z"),
                record("lease-release", "2025-01-01T00:45:00Z", "192.0.2.12", "released"),
                record("lease-assign", "2025-01-01T00:00:00Z", "2001:db8:1::", "v6",
                       "2025-01-01T03:00:00Z", **{"prefix-length": 64, "lease-type": "IA_PD"}),
                record("lease-assign", "2025-01-01T02:00:00Z", "192.0.2.10", "future",
                       "2025-01-01T04:00:00Z"),
            ]
            with gzip.open(str(base) + ".1.gz", "wt", encoding="utf-8") as rotated:
                rotated.write(json.dumps(records[0]) + "\n")
            base.write_text("".join(json.dumps(item) + "\n" for item in records[1:]),
                            encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = ip_audit_lookup.list_main([
                    str(base), "--at", "2025-01-01T01:00:00Z", "--json"])
            self.assertEqual(0, status)
            result = json.loads(output.getvalue())
            self.assertEqual(2, result["count"])
            self.assertEqual("audit-logs", result["source"])
            self.assertEqual(["192.0.2.10/32", "2001:db8:1::/64"],
                             [lease["network"] for lease in result["leases"]])
            self.assertEqual(records[1], result["leases"][0]["record"])
            self.assertEqual("2025-01-01T00:00:00Z", result["leases"][0]["start"])

    def test_list_omits_unknown_expiry_and_reports_empty_success(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            base.write_text(json.dumps(record(
                "lease-assign", "2025-01-01T00:00:00Z", "192.0.2.10", "unknown")) + "\n",
                encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                status = ip_audit_lookup.list_main([
                    str(base), "--at", "2025-01-01T01:00:00Z", "--json"])
            self.assertEqual(0, status)
            self.assertEqual([], json.loads(output.getvalue())["leases"])
            self.assertIn("unknown expiry", errors.getvalue())

    def test_list_reports_invalid_logs_and_snapshot_time(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "audit.log"
            base.write_text("not JSON\n", encoding="utf-8")
            for arguments in ([str(base), "--json"],
                              [str(base), "--at", "2025-01-01T00:00:00", "--json"]):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = ip_audit_lookup.list_main(arguments)
                self.assertEqual(2, status)
                self.assertEqual("", output.getvalue())
                self.assertIn("ip-audit-list:", errors.getvalue())

    def test_list_defaults_to_readable_and_supports_json_and_table(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "ip-audit-list"
            shutil.copyfile(ip_audit_lookup.__file__, command)
            base = Path(directory) / "audit.log"
            base.write_text(json.dumps(record(
                "lease-assign", "2000-01-01T00:00:00Z", "192.0.2.10", "client-a",
                "2999-01-01T00:00:00Z")) + "\n", encoding="utf-8")
            result = subprocess.run([sys.executable, str(command), str(base)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Active allocations: 1", result.stdout)
            self.assertIn("192.0.2.10/32", result.stdout)

            result = subprocess.run([sys.executable, str(command), "--json", str(base)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(1, json.loads(result.stdout)["count"])

            result = subprocess.run([sys.executable, str(command), "--table", str(base)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("network\tstart\tend", result.stdout)
            self.assertIn("192.0.2.10/32", result.stdout)


if __name__ == "__main__":
    unittest.main()