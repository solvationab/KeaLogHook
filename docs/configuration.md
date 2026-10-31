# Configuration reference

The hook is configured through the `parameters` of its entry in `hooks-libraries` in the
Kea configuration. Use `libdhcp_ip_audit.so` in `Dhcp4`, or `libdhcp6_ip_audit.so` in
`Dhcp6`; the sink parameters are the same for both libraries.

```json
{
  "library": "/usr/lib/kea/hooks/libdhcp_ip_audit.so",
  "parameters": {
    "queue-size": 10000,
    "sinks": [ { ... }, { ... } ]
  }
}
```

## Top-level parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `queue-size` | integer (1-1000000) | no | Maximum number of records waiting for sink delivery. Default: `10000`. When full, new records are dropped and counted; the count is logged when the hook unloads. |
| `sinks` | list of objects | yes | One or more sink definitions. Every record is delivered to each sink that subscribes to its event. |

Callouts enqueue records and return without waiting for sink writes. One worker delivers
records to sinks in FIFO order. Records already accepted into the queue are drained when
the hook unloads. A slow sink can fill the queue; records beyond its configured capacity
are dropped rather than delaying DHCP processing. Sink failures are logged and do not
prevent delivery to other sinks.

## Parameters common to all sinks

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `type` | string | required | Sink implementation: `file` or `zeromq`. |
| `name` | string | `<type>-<index>` | Name used in log messages. |
| `events` | list of strings | all events | Events this sink receives. See [fields.md](fields.md#events). |
| `format` | string or object | `json` | How a record is turned into text. See below. |

Unknown parameters are rejected and prevent the library from loading.

The following optional parameters can be used on either sink type:

- `renewals-on-change` (boolean, default `false`) suppresses an unchanged `lease-renew` for
  this sink. A renewal is logged when its IP is first seen or its MAC/client identity or relay
  metadata changes. The per-sink cache holds up to 100,000 IP addresses; when full, a cached
  entry is evicted, so a later renewal for it may be logged again.
- `renewal-rate-limit` (integer, `0`-`1000000`, default `0`) sets the maximum `lease-renew`
  records per second for this sink. It uses a token bucket with a burst capacity equal to the
  limit; `0` disables rate limiting. Other event types are unaffected.

Both settings are disabled when omitted, preserving the default behavior of logging every
renewal.

## Formats

The `format` parameter can be omitted (JSON with all non-empty fields), a string
(`"json"`), or an object.

### `json`

```json
"format": {
  "type": "json",
  "fields": ["timestamp", "event", "ip-address", "hw-address", "vendor-class-text",
             "user-class", "circuit-id", "relay-flags", "relay-vendor-specific", "pop", "site"],
  "include-empty": false
}
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fields` | list of strings | all fields | Fields to include, in the given order. Must be names from [fields.md](fields.md#fields). |
| `include-empty` | boolean | `false` | Include fields whose value is empty (`""`, or `null` for numeric fields). |

String fields are JSON strings; `subnet-id` and `valid-lifetime` are JSON numbers.

### `template`

```json
"format": {
  "type": "template",
  "template": "%{timestamp} %{event} ip=%{ip-address} mac=%{hw-address} circuit=%{circuit-id}"
}
```

`%{name}` is replaced by the field value; a field with no value expands to an empty
string. Unknown field names and unterminated placeholders are rejected at load time.
Any other text is copied verbatim.

## `file` sink

Appends one formatted record per line.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | string | required | Path of the log file. The directory must exist and be writable by the Kea user. |
| `file-mode` | octal string | `"0640"` | Permission bits used when the file is created. |
| `max-size` | integer (bytes) | `0` | Rotate before the file would exceed this size. `0` disables rotation. |
| `max-files` | integer | `5` | Number of rotated files to keep (`path.1` is the newest). `0` deletes the file on rotation. |
| `fsync` | boolean | `false` | Call `fsync` after every record. Safer against power loss, slower. |

Records are written with unbuffered `write()` calls, so a record is never split across
buffered flushes. If the file cannot be opened at load time, loading fails.

## `zeromq` sink

Publishes records on a ZeroMQ `PUB` socket.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `endpoint` | string | required | ZeroMQ endpoint, e.g. `tcp://127.0.0.1:5556` or `ipc:///run/kea/audit.sock`. |
| `mode` | `"bind"` or `"connect"` | `"bind"` | Whether the hook binds the endpoint (subscribers connect) or connects to it (e.g. to an XSUB proxy). |
| `topic` | string | `""` | Topic template. May contain `%{field}` placeholders, e.g. `"ip-audit.%{event}"`. |
| `multipart` | boolean | `true` | `true`: send two frames, `[topic][payload]`. `false`: send one frame `"<topic> <payload>"` (or just the payload if the topic is empty). |
| `send-hwm` | integer | `1000` | Send high-water mark (messages queued per subscriber before dropping). `0` means unlimited. |
| `linger-ms` | integer | `1000` | How long unsent messages are kept when the library unloads. `-1` waits forever, `0` discards immediately. |
| `io-threads` | integer 1-64 | `1` | ZeroMQ I/O threads. |

ZeroMQ subscription filters match on a prefix of the first frame, so subscribers can
select events or any other topic structure you build with the `topic` template.

## Example

```json
"parameters": {
  "sinks": [
    {
      "type": "file",
      "name": "audit-file",
      "events": ["lease-assign", "lease-renew", "lease-delete", "lease-release"],
      "path": "/var/log/kea/ip-audit.log",
      "max-size": 104857600,
      "max-files": 10
    },
    {
      "type": "zeromq",
      "name": "audit-zmq",
      "endpoint": "tcp://127.0.0.1:5556",
      "topic": "ip-audit.%{event}"
    }
  ]
}
```

See [../examples/kea-dhcp4.conf](../examples/kea-dhcp4.conf) for a fuller example.
For DHCPv6, see [../examples/kea-dhcp6.conf](../examples/kea-dhcp6.conf).
