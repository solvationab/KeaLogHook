#!/usr/bin/env python3
"""Checks the audit hook's Kea control commands over a Unix socket."""

import json
import os
import socket
import sys
import time


def command(socket_path, name, arguments=None):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(socket_path)
        request = {"command": name}
        if arguments is not None:
            request["arguments"] = arguments
        client.sendall(json.dumps(request).encode("utf-8") + b"\n")
        response = bytearray()
        decoder = json.JSONDecoder()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
            text = response.decode("utf-8")
            start = len(text) - len(text.lstrip())
            try:
                result, _ = decoder.raw_decode(text, start)
                return result[0] if isinstance(result, list) else result
            except json.JSONDecodeError:
                continue
    finally:
        client.close()
    raise RuntimeError("no complete JSON response for " + name)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: control_client.py SOCKET AUDIT_LOG")
    socket_path, audit_log = sys.argv[1:]

    stats_response = command(socket_path, "ip-audit-stats")
    if stats_response.get("result") != 0:
        raise RuntimeError("ip-audit-stats failed: " + repr(stats_response))
    stats = stats_response.get("arguments", {})
    expected_stats = {
        "queue-depth": 0,
        "queue-capacity": 100,
        "sink-count": 1,
        "sink-writes": 4,
        "sink-write-failures": 0,
        "dropped-records": 0,
    }
    for key, expected in expected_stats.items():
        if stats.get(key) != expected:
            raise RuntimeError("%s is %r, expected %r" % (key, stats.get(key), expected))

    metric_name = "ip-audit-dhcp4-sink-writes"
    deadline = time.monotonic() + 5
    while True:
        metric_response = command(socket_path, "statistic-get", {"name": metric_name})
        samples = metric_response.get("arguments", {}).get(metric_name, [])
        if metric_response.get("result") == 0 and any(
            isinstance(sample, list) and sample and sample[0] == 4 for sample in samples
        ):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Kea statistic-get did not return four sink writes: " +
                               repr(metric_response))
        time.sleep(0.1)

    rotated_log = audit_log + ".external"
    os.rename(audit_log, rotated_log)
    reopen_response = command(socket_path, "ip-audit-reopen")
    if reopen_response.get("result") != 0:
        raise RuntimeError("ip-audit-reopen failed: " + repr(reopen_response))
    reopen = reopen_response.get("arguments", {})
    if reopen.get("reopened") != 1 or reopen.get("unsupported") != 0 or reopen.get("failed") != 0:
        raise RuntimeError("unexpected ip-audit-reopen response: " + repr(reopen_response))
    if not os.path.exists(audit_log) or os.path.getsize(audit_log) != 0:
        raise RuntimeError("file sink did not open a new log after reopen")

    print("control commands OK")


if __name__ == "__main__":
    main()