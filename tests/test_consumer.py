#!/usr/bin/env python3
import argparse
import contextlib
import csv
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

import zmq

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples" / "developer" / "python"))
import listener
import publisher


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.validator = listener.make_validator()
        self.records = [json.loads(line) for line in
                        (ROOT / "examples/developer/python/records.jsonl").read_text().splitlines()]

    def payload(self, **changes):
        record = dict(self.records[0], **changes)
        return json.dumps(record).encode()

    def test_example_topic_matches_subscription(self):
        config = json.loads((ROOT / "examples/sink-zeromq.json").read_text())
        self.assertTrue(config["topic"].startswith("ip-audit."))
        self.assertTrue(config["multipart"])
        self.assertEqual("json", config["format"])

    def test_fixtures_validate_against_exact_schema_and_cover_events(self):
        strict = listener.make_validator(strict=True)
        for record in self.records:
            self.assertEqual(record, listener.decode_record(json.dumps(record).encode(), strict))
        self.assertEqual({"lease-assign", "lease-renew", "lease-delete", "lease-release",
                          "lease-decline", "lease-expire"}, {record["event"] for record in self.records})
        self.assertEqual({"IA_NA", "IA_TA", "IA_PD"},
                         {record["lease-type"] for record in self.records if "lease-type" in record})
        self.assertEqual(r"\x00port\\7", self.records[0]["circuit-id-text"])
        expiry = next(record for record in self.records if record["event"] == "lease-expire")
        self.assertNotIn("circuit-id", expiry)

    def test_compatible_reader_preserves_unknown_fields_and_events(self):
        payload = self.payload(**{"schema-version": "1.2.0", "event": "future-event",
                                  "future-field": {"nested": 1}})
        record = listener.decode_record(payload, self.validator)
        self.assertEqual({"nested": 1}, record["future-field"])
        with self.assertRaises(ValueError):
            listener.decode_record(payload, listener.make_validator(strict=True))

    def test_rejects_wrong_major_version_and_invalid_core_fields(self):
        for changes in ({"schema-version": "2.0.0"}, {"schema-version": "1.01.0"},
                        {"timestamp": "yesterday"}, {"ip-address": "not-an-ip"},
                        {"subnet-id": "1"}, {"event": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                listener.decode_record(self.payload(**changes), self.validator)
        record = dict(self.records[0])
        del record["schema-version"]
        with self.assertRaises(ValueError):
            listener.decode_record(json.dumps(record).encode(), self.validator)

    def test_rejects_malformed_json_encoding_and_duplicate_keys(self):
        for payload in (b"{broken", b"\xff", b"[]", b'{"event":"a","event":"b"}',
                        b'{"extra":NaN}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                listener.decode_record(payload, self.validator)

    def test_multipart_and_empty_topic(self):
        for topic in (b"ip-audit.lease-assign", b""):
            decoded_topic, record = listener.decode_message([topic, self.payload()], self.validator)
            self.assertEqual(topic.decode(), decoded_topic)
            self.assertEqual("lease-assign", record["event"])
        for parts in ([self.payload()], [b"t", self.payload(), b"extra"], [b"\xff", self.payload()]):
            with self.assertRaises(ValueError):
                listener.decode_message(parts, self.validator)

    def test_default_json_and_table_outputs(self):
        for mode in ("human", "json", "table"):
            arguments = argparse.Namespace(json=mode == "json", table=mode == "table")
            stream = io.StringIO()
            listener.Output(arguments, stream).write("ip-audit.lease-assign", self.records[0])
            text = stream.getvalue()
            if mode == "json":
                self.assertEqual(self.records[0], json.loads(text)["record"])
            elif mode == "table":
                self.assertEqual("\t".join(listener.COLUMNS), text.splitlines()[0])
            else:
                self.assertIn("lease-assign | 192.0.2.10", text)

    def test_listener_rejects_conflicting_formats_and_invalid_limits(self):
        for arguments in (["--json", "--table"], ["--count", "-1"],
                          ["--timeout-ms", "-2"], ["--receive-hwm", "0"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                listener.main(arguments)
            self.assertEqual(2, error.exception.code)

    def test_publisher_framing_matches_hook(self):
        for single_frame in (False, True):
            for template in ("ip-audit.%{event}", ""):
                topic, parts = publisher.frames_for(self.records[0], template, single_frame)
                payload = json.dumps(self.records[0], separators=(",", ":")).encode()
                expected = ([topic.encode() + b" " + payload if topic else payload]
                            if single_frame else [topic.encode(), payload])
                self.assertEqual(expected, parts)

    def test_publisher_validates_fixtures_before_sending(self):
        self.assertEqual(self.records, publisher.load_records(publisher.FIXTURES_PATH))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            for text in ("", "{broken\n", '{"event":"lease-assign"}\n'):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    publisher.load_records(path)

    def test_publisher_formats_and_invalid_options(self):
        for arguments in (["--json", "--table"], ["--repeat", "0"],
                          ["--interval-ms", "-1"], ["--wait-ms", "0"],
                          ["--send-hwm", "-1"], ["--restart-every", "-1"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                publisher.main(arguments)
            self.assertEqual(2, error.exception.code)

    def test_listener_idle_timeout_and_keyboard_interrupt(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, listener.main(["--endpoint", "tcp://127.0.0.1:1", "--timeout-ms", "1"]))
        from unittest.mock import patch
        with patch.object(listener, "run", side_effect=KeyboardInterrupt):
            self.assertEqual(0, listener.main([]))
        with patch.object(publisher, "run", side_effect=KeyboardInterrupt):
            self.assertEqual(0, publisher.main([]))

    def test_fixture_publisher_sends_burst_and_malformed_frames(self):
        with zmq.Context() as context:
            with context.socket(zmq.SUB) as subscriber:
                subscriber.setsockopt(zmq.LINGER, 0)
                subscriber.setsockopt(zmq.SUBSCRIBE, b"ip-audit.")
                endpoint = "inproc://consumer-" + uuid.uuid4().hex
                subscriber.connect(endpoint)
                arguments = argparse.Namespace(endpoint=endpoint, wait_ms=5000, send_hwm=1000,
                    topic="ip-audit.%{event}", single_frame=False, interval_ms=0, malformed="frames",
                    json=True, table=False)
                stream = io.StringIO()
                result = []

                def send():
                    try:
                        result.append(publisher.publish_batch(arguments, self.records,
                                      listener.Output(arguments, stream), context, 2))
                    except Exception as error:
                        result.append(error)

                worker = threading.Thread(target=send)
                worker.start()
                try:
                    received = []
                    for number in range(2 * (len(self.records) + 1)):
                        self.assertTrue(subscriber.poll(5000), "fixture message not received")
                        received.append(subscriber.recv_multipart())
                finally:
                    worker.join(10)
                self.assertFalse(worker.is_alive())
                self.assertEqual([0], result)
                self.assertEqual(2, sum(len(parts) == 3 for parts in received))
                self.assertEqual(2 * len(self.records), len(stream.getvalue().splitlines()))

    def test_publisher_startup_timeout(self):
        arguments = argparse.Namespace(endpoint="inproc://absent-" + uuid.uuid4().hex,
            wait_ms=1, send_hwm=1000, json=False, table=False)
        with zmq.Context() as context, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(1, publisher.publish_batch(arguments, self.records,
                             listener.Output(arguments, io.StringIO()), context, 1))

    def test_publisher_restart_schedule_and_failure_status(self):
        from unittest.mock import patch
        arguments = argparse.Namespace(fixtures=publisher.FIXTURES_PATH, repeat=5,
                                       restart_every=2, json=False, table=False)
        with patch.object(publisher, "publish_batch", return_value=0) as send:
            self.assertEqual(0, publisher.run(arguments))
            self.assertEqual([2, 2, 1], [call.args[-1] for call in send.call_args_list])
        with patch.object(publisher, "publish_batch", return_value=1) as send:
            self.assertEqual(1, publisher.run(arguments))
            self.assertEqual(1, send.call_count)

    def test_cli_reports_fixture_and_socket_errors(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(2, publisher.main(["--fixtures", "missing-consumer-fixtures.jsonl"]))
            self.assertEqual(2, listener.main(["--endpoint", "unsupported://example"]))

    def test_real_listener_rejects_bad_payload_and_reconnects_after_restart(self):
        with zmq.Context() as context:
            first = context.socket(zmq.XPUB)
            first.setsockopt(zmq.LINGER, 0)
            port = first.bind_to_random_port("tcp://127.0.0.1")
            endpoint = "tcp://127.0.0.1:{}".format(port)
            process = subprocess.Popen([sys.executable, "-B", str(ROOT / "examples/developer/python/listener.py"),
                "--endpoint", endpoint, "--count", "2", "--timeout-ms", "10000", "--json"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(publisher.wait_for_subscription(first, 10000))
                first.send_multipart(publisher.malformed_frames("json"))
                first.send_multipart([b"ip-audit.lease-assign", self.payload()])
                first_output = process.stdout.readline()
                self.assertEqual("lease-assign", json.loads(first_output)["record"]["event"])
                first.close()
                with context.socket(zmq.XPUB) as second:
                    second.setsockopt(zmq.LINGER, 0)
                    second.bind(endpoint)
                    self.assertTrue(publisher.wait_for_subscription(second, 10000))
                    second.send_multipart([b"ip-audit.lease-renew", self.payload(event="lease-renew")])
                    output, errors = process.communicate(timeout=15)
                self.assertEqual(0, process.returncode, errors)
                self.assertIn("Rejected message", errors)
                self.assertEqual(["lease-assign", "lease-renew"],
                                 [json.loads(line)["record"]["event"]
                                  for line in (first_output + output).splitlines()])
            finally:
                first.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


class DotnetConsumerTests(unittest.TestCase):
    listener_path = None

    @classmethod
    def setUpClass(cls):
        if cls.listener_path is None:
            raise unittest.SkipTest("Use --dotnet-listener PATH to test the built NetMQ listener")
        cls.records = publisher.load_records(publisher.FIXTURES_PATH)

    def command(self, *arguments):
        return ["dotnet", str(self.listener_path)] + list(arguments)

    def receive(self, parts, *arguments, count=1):
        with zmq.Context() as context:
            with context.socket(zmq.XPUB) as socket:
                socket.setsockopt(zmq.LINGER, 0)
                port = socket.bind_to_random_port("tcp://127.0.0.1")
                process = subprocess.Popen(self.command("--endpoint", "tcp://127.0.0.1:{}".format(port),
                    "--count", str(count), "--timeout-ms", "3000", *arguments),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertTrue(publisher.wait_for_subscription(socket, 10000))
                    for message in parts:
                        socket.send_multipart(message)
                    output, errors = process.communicate(timeout=15)
                    return process.returncode, output, errors
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)

    def test_all_fixtures_and_output_formats(self):
        parts = [publisher.frames_for(record, "ip-audit.%{event}")[1] for record in self.records]
        for arguments in ([], ["--json"], ["--table"]):
            with self.subTest(arguments=arguments):
                status, output, errors = self.receive(parts, "--strict-schema", *arguments,
                                                      count=len(self.records))
                self.assertEqual(0, status, errors)
                self.assertEqual("", errors)
                if arguments == ["--json"]:
                    self.assertEqual(self.records, [json.loads(line)["record"] for line in output.splitlines()])
                elif arguments == ["--table"]:
                    rows = list(csv.reader(io.StringIO(output), delimiter="\t"))
                    self.assertEqual(list(listener.COLUMNS), rows[0])
                    self.assertEqual(len(self.records) + 1, len(rows))
                else:
                    self.assertIn("lease-assign | 192.0.2.10", output)

    def test_compatible_reader_rejects_bad_messages_and_preserves_future_data(self):
        record = dict(self.records[0], **{"schema-version": "1.2.0", "event": "future-event",
                                         "future-field": {"nested": "value"}})
        parts = [publisher.malformed_frames(kind) for kind in ("json", "utf8", "frames")]
        parts += [[b"ip-audit.invalid", b'{"event":"a","event":"b"}'],
                  [b"ip-audit.invalid", b'{"extra":NaN}']]
        for changes in ({"schema-version": "2.0.0"}, {"timestamp": "yesterday"},
                        {"ip-address": "not-an-ip"}, {"subnet-id": "1"}):
            parts.append(publisher.frames_for(dict(self.records[0], **changes), "ip-audit.invalid")[1])
        parts.append(publisher.frames_for(record, "ip-audit.%{event}")[1])
        status, output, errors = self.receive(parts, "--json")
        self.assertEqual(0, status, errors)
        self.assertEqual(record, json.loads(output)["record"])
        self.assertEqual(len(parts) - 1, errors.count("Rejected message:"))

    def test_strict_schema_and_empty_topic(self):
        future = dict(self.records[0], **{"schema-version": "1.2.0", "new-field": "value"})
        parts = [publisher.frames_for(record, "")[1] for record in (future, self.records[0])]
        status, output, errors = self.receive(parts, "--strict-schema", "--topic", "", "--json")
        self.assertEqual(0, status, errors)
        self.assertEqual("", json.loads(output)["topic"])
        self.assertEqual(self.records[0], json.loads(output)["record"])
        self.assertEqual(1, errors.count("Rejected message:"))

    def test_table_quotes_tabs_newlines_and_quotes(self):
        record = dict(self.records[0], server='dhcp\t"node"\nsecond')
        status, output, errors = self.receive([publisher.frames_for(record, "ip-audit.test")[1]], "--table")
        self.assertEqual(0, status, errors)
        rows = list(csv.reader(io.StringIO(output), delimiter="\t"))
        self.assertEqual(record["server"], rows[1][-1])

    def test_cli_help_and_invalid_options(self):
        result = subprocess.run(self.command("--help"), capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode)
        self.assertIn("NetMQ", result.stdout)
        for arguments in (["--json", "--table"], ["--count", "-1"], ["--count", "many"],
                          ["--count", "999999999999"], ["--timeout-ms", "-2"],
                          ["--receive-hwm", "0"], ["--endpoint"], ["--unknown"],
                          ["--schema", "missing-audit-schema.json"], ["--endpoint", "unsupported://test"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run(self.command(*arguments), capture_output=True, text=True, timeout=15)
                self.assertEqual(2, result.returncode, result.stderr)

    def test_idle_timeout(self):
        result = subprocess.run(self.command("--endpoint", "tcp://127.0.0.1:1", "--timeout-ms", "10"),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("idle timeout", result.stderr)

    def test_tcp_reconnect(self):
        with zmq.Context() as context:
            first = context.socket(zmq.XPUB)
            first.setsockopt(zmq.LINGER, 0)
            port = first.bind_to_random_port("tcp://127.0.0.1")
            endpoint = "tcp://127.0.0.1:{}".format(port)
            process = subprocess.Popen(self.command("--endpoint", endpoint, "--json", "--count", "2",
                "--timeout-ms", "10000"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(publisher.wait_for_subscription(first, 10000))
                first.send_multipart(publisher.frames_for(self.records[0], "ip-audit.%{event}")[1])
                first_output = process.stdout.readline()
                self.assertEqual(self.records[0], json.loads(first_output)["record"])
                first.close()
                with context.socket(zmq.XPUB) as second:
                    second.setsockopt(zmq.LINGER, 0)
                    second.bind(endpoint)
                    self.assertTrue(publisher.wait_for_subscription(second, 10000))
                    second.send_multipart(publisher.frames_for(self.records[1], "ip-audit.%{event}")[1])
                    output, errors = process.communicate(timeout=15)
                self.assertEqual(0, process.returncode, errors)
                self.assertEqual(self.records[:2],
                                 [json.loads(line)["record"] for line in (first_output + output).splitlines()])
            finally:
                first.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--dotnet-listener", type=Path)
    options, remaining = parser.parse_known_args()
    DotnetConsumerTests.listener_path = options.dotnet_listener
    unittest.main(argv=[sys.argv[0]] + remaining)