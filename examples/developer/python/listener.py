#!/usr/bin/env python3
"""Reference multipart JSON consumer; see docs/developer/integration.md."""

import argparse
import copy
import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

import zmq
from jsonschema import Draft202012Validator, FormatChecker


SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "audit-record.schema.json"
COLUMNS = ("topic", "timestamp", "event", "ip-address", "address-family", "server")


def make_validator(strict=False, schema_path=SCHEMA_PATH):
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    if not strict:
        schema = copy.deepcopy(schema)
        schema["additionalProperties"] = True
        schema["properties"]["schema-version"] = {
            "type": "string", "pattern": r"^1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
        }
        schema["properties"]["event"] = {"type": "string", "minLength": 1}
    return Draft202012Validator(schema, format_checker=FormatChecker())


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-standard JSON numeric constant")


def decode_record(payload, validator):
    try:
        record = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    except (UnicodeError, ValueError) as error:
        raise ValueError("invalid UTF-8 or JSON payload") from error
    error = next(validator.iter_errors(record), None)
    if error is not None:
        location = ".".join(str(part) for part in error.absolute_path) or "record"
        raise ValueError("invalid {} ({})".format(location, error.validator))
    try:
        ipaddress.ip_address(record["ip-address"])
    except ValueError as error:
        raise ValueError("invalid ip-address") from error
    return record


def decode_message(parts, validator):
    if len(parts) != 2:
        raise ValueError("expected exactly two frames: topic and JSON payload")
    try:
        topic = parts[0].decode("utf-8")
    except UnicodeError as error:
        raise ValueError("invalid UTF-8 topic") from error
    return topic, decode_record(parts[1], validator)


def add_output_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="emit complete JSON envelopes")
    group.add_argument("--table", action="store_true", help="emit tab-separated summary columns")


class Output:
    def __init__(self, arguments, stream=None):
        self.arguments = arguments
        self.stream = stream if stream is not None else sys.stdout
        self.writer = csv.writer(self.stream, delimiter="\t", lineterminator="\n")
        if arguments.table:
            self.writer.writerow(COLUMNS)

    def write(self, topic, record):
        if self.arguments.json:
            print(json.dumps({"topic": topic, "record": record}, separators=(",", ":"),
                             allow_nan=False), file=self.stream, flush=True)
        elif self.arguments.table:
            self.writer.writerow([topic] + [record.get(name, "") for name in COLUMNS[1:]])
            self.stream.flush()
        else:
            values = [topic] + [str(record.get(name, "-")) for name in COLUMNS[1:]]
            print(" | ".join(re.sub(r"[\x00-\x1f\x7f]", "?", value) for value in values),
                  file=self.stream, flush=True)


def run(arguments):
    validator = make_validator(arguments.strict_schema)
    output = Output(arguments)
    accepted = 0
    with zmq.Context() as context:
        with context.socket(zmq.SUB) as socket:
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVHWM, arguments.receive_hwm)
            socket.setsockopt(zmq.SUBSCRIBE, arguments.topic.encode("utf-8"))
            socket.connect(arguments.endpoint)
            while arguments.count == 0 or accepted < arguments.count:
                if not socket.poll(arguments.timeout_ms, zmq.POLLIN):
                    print("No record received before the idle timeout; check publisher and topic.",
                          file=sys.stderr)
                    return 1
                try:
                    topic, record = decode_message(socket.recv_multipart(), validator)
                except ValueError as error:
                    print("Rejected message: {}".format(error), file=sys.stderr)
                    continue
                output.write(topic, record)
                accepted += 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="tcp://127.0.0.1:5556")
    parser.add_argument("--topic", default="ip-audit.", help="subscription prefix; empty matches all")
    parser.add_argument("--count", type=int, default=0, help="accepted records before exit; 0 is unlimited")
    parser.add_argument("--timeout-ms", type=int, default=30000, help="idle timeout; -1 waits indefinitely")
    parser.add_argument("--receive-hwm", type=int, default=1000)
    parser.add_argument("--strict-schema", action="store_true", help="require the exact published schema")
    add_output_options(parser)
    arguments = parser.parse_args(argv)
    if arguments.count < 0 or arguments.timeout_ms < -1 or arguments.receive_hwm < 1:
        parser.error("count must be nonnegative, timeout-ms at least -1, and receive-hwm positive")
    try:
        return run(arguments)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, zmq.ZMQError) as error:
        print("Listener failed: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())