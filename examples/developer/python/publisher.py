#!/usr/bin/env python3
"""Synthetic ZeroMQ publisher for consumer tests; never sends DHCP traffic."""

import argparse
import json
import sys
import threading
import time
from pathlib import Path

import zmq

from listener import Output, add_output_options, decode_record, make_validator


FIXTURES_PATH = Path(__file__).with_name("records.jsonl")


def load_records(path):
    validator = make_validator(strict=True)
    records = []
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    records.append(decode_record(line.encode("utf-8"), validator))
                except ValueError as error:
                    raise ValueError("fixture line {}: {}".format(number, error)) from error
    if not records:
        raise ValueError("fixture file contains no records")
    return records


def frames_for(record, topic_template, single_frame=False):
    topic = topic_template.replace("%{event}", record["event"])
    payload = json.dumps(record, separators=(",", ":"), allow_nan=False).encode("utf-8")
    encoded_topic = topic.encode("utf-8")
    if single_frame:
        return topic, [encoded_topic + b" " + payload if encoded_topic else payload]
    return topic, [encoded_topic, payload]


def wait_for_subscription(socket, timeout_ms):
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        remaining = max(0, int((deadline - time.monotonic()) * 1000))
        if not socket.poll(remaining, zmq.POLLIN):
            return False
        notification = socket.recv()
        if notification and notification[0] == 1:
            return True
        if time.monotonic() >= deadline:
            return False


def malformed_frames(kind):
    if kind == "json":
        return [b"ip-audit.invalid", b"{broken"]
    if kind == "utf8":
        return [b"ip-audit.invalid", b"\xff"]
    return [b"ip-audit.invalid", b"{}", b"extra"]


def publish_batch(arguments, records, output, context, rounds):
    with context.socket(zmq.XPUB) as socket:
        socket.setsockopt(zmq.LINGER, 1000)
        socket.setsockopt(zmq.SNDHWM, arguments.send_hwm)
        socket.bind(arguments.endpoint)
        if not wait_for_subscription(socket, arguments.wait_ms):
            print("No subscription received before the startup timeout.", file=sys.stderr)
            return 1
        for round_number in range(rounds):
            for record in records:
                topic, parts = frames_for(record, arguments.topic, arguments.single_frame)
                socket.send_multipart(parts, flags=zmq.DONTWAIT)
                output.write(topic, record)
                if arguments.interval_ms:
                    threading.Event().wait(arguments.interval_ms / 1000)
            if arguments.malformed != "none":
                socket.send_multipart(malformed_frames(arguments.malformed), flags=zmq.DONTWAIT)
                print("Published malformed message ({})".format(arguments.malformed), file=sys.stderr)
    return 0


def run(arguments):
    records = load_records(arguments.fixtures)
    output = Output(arguments)
    remaining = arguments.repeat
    with zmq.Context() as context:
        while remaining:
            rounds = min(remaining, arguments.restart_every or remaining)
            status = publish_batch(arguments, records, output, context, rounds)
            if status:
                return status
            remaining -= rounds
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="tcp://127.0.0.1:5557")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_PATH)
    parser.add_argument("--topic", default="ip-audit.%{event}", help="literal topic or %%{event} template")
    parser.add_argument("--single-frame", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--interval-ms", type=int, default=100, help="0 publishes a burst")
    parser.add_argument("--wait-ms", type=int, default=10000, help="startup subscription timeout")
    parser.add_argument("--send-hwm", type=int, default=1000, help="0 means unlimited")
    parser.add_argument("--restart-every", type=int, default=0, help="rebind after this many fixture rounds")
    parser.add_argument("--malformed", choices=("none", "json", "utf8", "frames"), default="none")
    add_output_options(parser)
    arguments = parser.parse_args(argv)
    if (arguments.repeat < 1 or arguments.interval_ms < 0 or arguments.wait_ms < 1
            or arguments.send_hwm < 0 or arguments.restart_every < 0):
        parser.error("repeat and wait-ms must be positive; other numeric options must be nonnegative")
    try:
        return run(arguments)
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, zmq.ZMQError) as error:
        print("Publisher failed: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())