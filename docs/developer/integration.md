# Developing an audit consumer

Use the ZeroMQ sink for live notifications to your application. It is best-effort PUB/SUB,
not a durable event stream or a query of Kea's current leases. Read the
[wire contract](wire-format.md), [compatibility policy](compatibility.md), and
[recovery guidance](recovery.md) before using events to maintain application state.
The [field reference](../fields.md) defines event meanings and identifier encodings.

## Quick start

The reference examples require Python 3.10+ and the dependencies in
[requirements.txt](../../examples/developer/requirements.txt). This requirement applies
only to these examples, not the installed audit CLI commands. From a source checkout or
extracted release documentation archive:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r examples/developer/requirements.txt
```

On Windows, use `py -3.13 -m venv .venv` and `.venv\Scripts\python.exe` instead. Debian/Ubuntu
may require the `python3-venv` package. Keep the relative `docs/` and `examples/` layout:
the listener loads the published schema from that tree. These are source examples, not
new commands installed in `/usr/bin`.

### Without a DHCP server

In one terminal, start the [reference listener](../../examples/developer/listener.py):

```sh
.venv/bin/python examples/developer/listener.py --endpoint tcp://127.0.0.1:5557
```

In another terminal, start the [fixture publisher](../../examples/developer/publisher.py):

```sh
.venv/bin/python examples/developer/publisher.py
```

The publisher waits up to 10 seconds for a subscription before sending. It uses XPUB to
observe subscription notifications for repeatable tests; it does not implement a readiness
handshake with your application. The real hook uses PUB and does not wait for subscribers.
Port `5557` deliberately differs from the hook example's `5556`. Use an unused port and
keep this synthetic traffic separate from production endpoints and databases.

### With the hook

Add [sink-zeromq.json](../../examples/sink-zeromq.json) to the hook's `sinks` list. It binds
`tcp://127.0.0.1:5556`, sends multipart JSON, and publishes topics such as
`ip-audit.lease-assign`. Start the listener on that host:

```sh
.venv/bin/python examples/developer/listener.py --json
```

Generate a new lease event; enabling the hook does not publish existing leases. An example
received envelope is:

```json
{"topic":"ip-audit.lease-assign","record":{"timestamp":"2026-11-07T12:00:00.123Z","event":"lease-assign","schema-version":"1.0.0","ip-address":"192.0.2.10"}}
```

The envelope is listener output, not an additional frame or wrapper emitted by the hook.
Actual default records include every available non-empty field.

## Reference listener behavior

The listener sets its subscription before connecting and expects exactly two frames with
a UTF-8 topic and JSON payload. It validates the core record, known field types, timestamps
and IP address; malformed JSON, duplicate keys, non-standard numeric constants and invalid
encoding are rejected. Errors go to stderr and do not stop later valid records. The listener
prints records; it does not reconstruct leases or apply business side effects.

Default validation accepts version `1.x.y`, unknown fields and unknown event names while
preserving complete records. `--strict-schema` requires the exact published `1.0.0` schema.
See [Compatibility](compatibility.md) for why those are different modes.

Useful options:

- `--topic ip-audit.lease-renew` selects a prefix, not an exact topic. `--topic ''` receives
  all topics, including the empty topic used when the hook's `topic` option is omitted.
- `--count 9` exits after nine accepted records; rejected records are not counted. `0`
  (the default) is unlimited.
- `--timeout-ms 30000` is the default idle poll timeout. `-1` waits indefinitely. An idle
  timeout is not proof of a broken connection: traffic may simply be absent or filtered.
- `--receive-hwm 1000` bounds the local receive queue. Keep processing fast or introduce a
  bounded downstream queue with an explicit overflow policy.
- Ctrl+C closes the socket and context cleanly, discarding pending local socket messages.

The example supports only multipart JSON. A single-frame or template publisher requires
an intentionally different decoder; do not silently reinterpret malformed messages.

## Output and exit status

Both scripts default to a readable summary. `--json` and `--table` are mutually exclusive.
JSON emits one complete `{"topic": ..., "record": ...}` envelope per accepted/published
record, preserving unknown fields. The topic is not inferred from the event.

Table output is tab-separated with stable columns:
`topic`, `timestamp`, `event`, `ip-address`, `address-family`, `server`.
Missing optional values are empty; other fields, including client and relay identifiers,
are omitted from the table. CSV quoting protects tabs and newlines inside table cells;
use a TSV-capable parser rather than splitting each line on tabs. Human summaries replace
control characters for display. These summaries are not lossless audit archives.

Exit statuses are `0` for normal completion or Ctrl+C, `1` for the listener idle timeout or
publisher subscription timeout, and `2` for command-line, fixture, schema-loading or socket
errors. Rejected incoming messages are reported on stderr but do not change eventual success
status. Publisher stdout reports send attempts, not verified receipt; malformed injections
are reported only on stderr and have no JSON/table record row.

## Fixtures and consumer tests

[records.jsonl](../../examples/developer/records.jsonl) contains nine synthetic records:
all six event types, IPv4, IPv6 IA_NA/IA_TA, an IA_PD `/56`, missing relay data, and a binary
circuit ID containing NUL and a literal backslash. They conform to the exact published JSON
schema. They are a parser corpus, not a chronological or complete lease history. Addresses
come from documentation ranges; timestamps, hostnames and identities are invented.

Read each line as a separate JSON record. For example, the first record's
`circuit-id-text` is the literal text `\x00port\\7` after JSON decoding, not raw NUL bytes.
Use the corresponding `circuit-id` hex value when exact binary identity matters.

The publisher supports a literal `--topic` or the `%{event}` placeholder, including an empty
topic. `--single-frame` reproduces the alternative framing. To exercise bursts and repeated
records, while the listener remains running:

```sh
.venv/bin/python examples/developer/publisher.py --repeat 100 --interval-ms 0 --send-hwm 10
.venv/bin/python examples/developer/publisher.py --malformed json
.venv/bin/python examples/developer/publisher.py --malformed utf8
.venv/bin/python examples/developer/publisher.py --malformed frames
.venv/bin/python examples/developer/publisher.py --repeat 4 --restart-every 1
```

`--malformed` appends one invalid multipart message per fixture round. The literal injection
topic is `ip-audit.invalid`, independent of `--topic`; subscribe to `ip-audit.` to receive it.
`--restart-every` closes and rebinds the publishing socket after the selected number of
rounds, then waits for a new subscription. This exercises socket reconnects, not process
crashes or durable recovery. Rerun the script to exercise a process restart. Do not assert
an exact drop count in burst tests: ZeroMQ high-water marks are not a deterministic loss
generator. The fixture timestamps remain unchanged on repetition, intentionally giving
your consumer repeated records to test.

Use `--fixtures path/to/records.jsonl` for a custom corpus. The publisher validates the
entire file against the exact schema before binding or sending. Additional malformed cases
should use explicit injections rather than corrupting the valid fixtures.

Run the example test suite from a source checkout:

```sh
.venv/bin/python -B tests/test_consumer.py
```

Tests cover framing, fixtures, strict and compatible readers, output formats, validation
failures, bursts, timeouts, clean interruption, and TCP reconnects after publisher restart.
They require neither Kea nor root. CI runs them in a separate virtual environment.