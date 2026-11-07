# ZeroMQ wire contract

The hook creates a ZeroMQ PUB socket. In default `mode: "bind"`, the hook binds and a SUB
consumer connects. In `mode: "connect"`, the hook connects to an endpoint provided by a
compatible subscriber or XSUB proxy. This transport is ZeroMQ, not raw TCP, HTTP, or a
newline-delimited TCP protocol. Use a maintained ZeroMQ binding for your language.
See [sink configuration](../configuration.md#zeromq-sink) for all transport settings.

## Recommended integration configuration

Use [sink-zeromq.json](../../examples/sink-zeromq.json):

```json
{
  "type": "zeromq",
  "endpoint": "tcp://127.0.0.1:5556",
  "topic": "ip-audit.%{event}",
  "multipart": true,
  "format": "json"
}
```

These explicit settings are recommendations, not different runtime defaults. When omitted,
`topic` is empty, `multipart` is `true`, and `format` is JSON with all non-empty fields.
The sink `name` is used for diagnostics; unlike syslog, it is not prefixed to the payload.
Two sinks or DHCP processes may use different topic or field configurations; consumers must
agree those settings with the publisher administrator.

## Multipart mode

Each message consists of exactly two frames, delivered together as one multipart message:

```text
Frame 0: ip-audit.lease-assign
Frame 1: {"timestamp":"2026-11-07T12:00:00.123Z","event":"lease-assign","schema-version":"1.0.0","ip-address":"192.0.2.10"}
```

With an empty topic, frame 0 is still present and has zero bytes. There is no length field,
delimiter frame, JSON envelope, trailing newline, or terminating NUL added by the hook.
The payload example above is abbreviated to core fields; the default formatter includes
other non-empty fields as well. Treat frames as bytes before decoding and use your binding's
multipart receive API, not a single receive that ignores subsequent frames.

## Single-frame mode

With `multipart: false` and a non-empty topic, the message is one frame:

```text
ip-audit.lease-assign {"timestamp":"2026-11-07T12:00:00.123Z","event":"lease-assign","schema-version":"1.0.0","ip-address":"192.0.2.10"}
```

One ASCII space separates topic and payload. With an empty topic, the frame is just the
payload, without a leading space. Topics containing spaces make this split ambiguous;
choose space-free topics or use multipart. A subscriber filtering the first frame sees the
topic prefix in either mode, or the payload itself when no topic is set in single-frame mode.

## Topic subscriptions

ZeroMQ filters are byte-prefix matches on the first frame. `ip-audit.` matches all topics
in the recommended configuration. `ip-audit.lease-renew` also matches a hypothetical
`ip-audit.lease-renew.extra`; check the full topic after receiving if exact matching matters.
An empty subscription matches every message. No subscriptions means no received messages.

Set subscriptions before connecting to reduce startup races, but subscription propagation
is asynchronous and does not remove startup loss. Topics are configurable templates using
the [field names](../fields.md); do not treat them as authoritative event types. Parse the
payload's `event` and explicitly handle any mismatch with an application-agreed topic policy.

## JSON payload and text encodings

The JSON formatter emits one compact JSON object. Property order follows the field list,
but consumers must not depend on property order. String fields are strings and numeric fields
are numbers, with `null` for empty numeric fields only when `include-empty` is enabled.
Default output omits empty fields; a custom field selection can omit even core properties.
See [Compatibility](compatibility.md) before validating a projected record.

Use UTF-8 for integration configuration and decode topic/payload bytes strictly. The sink
does not add a character-set marker or transcode arbitrary configured text; report invalid
encoding instead of silently replacing bytes that might identify a subscriber. The formatter
escapes JSON quotes, backslashes and bytes below `0x20`. Binary relay data has explicit hex
fields and escaped text companions, not raw binary JSON values.

For bytes `00 70 6f 72 74 5c 37`:

```json
{"circuit-id":"00706f72745c37","circuit-id-text":"\\x00port\\\\7"}
```

After JSON decoding, the text value is `\x00port\\7`. The `\x00` sequence is literal text
representing a byte, not a JSON escape or an embedded NUL. Do not indiscriminately unescape
the text again; use the hex field for exact binary comparisons. Hex separator conventions
differ between fields; consult the [field reference](../fields.md).

## Template payloads

`format: {"type": "template", "template": "..."}` replaces the JSON frame with expanded
text. Framing and topic filtering remain the same. There is no universal schema or escaping
contract for arbitrary templates; their layout is an agreement between publisher and consumer.
The JSON reference listener deliberately rejects these payloads.