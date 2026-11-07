# .NET listener with NetMQ

[AuditListener.csproj](../../examples/developer/dotnet/AuditListener.csproj) is a runnable
.NET 10 console example using [NetMQ](https://github.com/zeromq/netmq), a managed ZeroMQ
implementation, and JsonSchema.Net for JSON Schema validation. No native libzmq installation
is needed by this listener. Install the .NET 10 SDK to build it; `dotnet restore` retrieves
the pinned NuGet dependencies automatically during the first build.

The example follows the same [wire contract](wire-format.md) and
[compatibility policy](compatibility.md) as the Python listener. It is a starting point for
an application integration, not a durable queue, a live lease query, or a hardened service.
Read [Delivery, recovery and security](recovery.md) before maintaining application state.

## Build and run

From a source checkout or extracted release documentation archive:

```sh
dotnet build examples/developer/dotnet/AuditListener.csproj --configuration Release --artifacts-path build/netmq
dotnet build/netmq/bin/AuditListener/release/AuditListener.dll --endpoint tcp://127.0.0.1:5557 --json
```

The same commands work in PowerShell. In a second terminal, run the Python
[fixture publisher](../../examples/developer/python/publisher.py) after installing its dependencies
as described in the [integration guide](integration.md#quick-start):

```sh
.venv/bin/python examples/developer/python/publisher.py
```

On Windows, use `.venv\Scripts\python.exe` for that command. The publisher waits for a
subscription before sending the nine synthetic fixtures. Neither Kea nor root is needed.
To connect to the real hook, use the [ZeroMQ sink example](../../examples/sink-zeromq.json)
and omit `--endpoint` (the listener defaults to `tcp://127.0.0.1:5556`). Trigger a new lease
event; the hook does not backfill existing leases. Use TCP endpoints for this NetMQ example;
do not assume the hook's `ipc://` transport is supported by NetMQ.

The project copies the published audit schema beside its executable, both on build and
publish. Keep the project and `docs/` in their shipped relative layout when building.
After building, the output directory is self-contained apart from the .NET runtime, so
running the DLL does not depend on the current working directory. Keep NuGet dependency
DLLs and the schema alongside it. Build artifacts are written outside `examples/` to keep
the documentation tree clean; packaging also excludes local `bin` and `obj` directories.

## Receiving records

[Program.cs](../../examples/developer/dotnet/Program.cs) owns a single `SubscriberSocket`
on the main thread, subscribes before connecting, and receives complete multipart messages
with `TryReceiveMultipartMessage`. Each message must have exactly two frames: topic bytes
and JSON payload bytes. Both are decoded with strict UTF-8. An empty topic frame is valid.
Single-frame and template payloads are deliberately not supported by this decoder.

The listener rejects invalid JSON, duplicate property names (including nested objects),
invalid encodings, schema violations and invalid IP addresses. Validation explicitly enables
JSON Schema format checks, including timestamps. Rejected messages are reported on stderr
without dumping their payload and do not prevent later valid records from being received.

Default reading accepts `schema-version` values matching `1.x.y`, preserves unknown fields,
and prints unknown event names without assigning lease semantics to them. `--strict-schema`
uses the exact published schema, including its version, property list and event enumeration.
Both modes require the four core fields. Intentional projections missing those fields need
a separately agreed decoder/schema, not relaxed guesses.

For integration, replace `WriteRecord` with a bounded handoff to your application's processor.
Retain `JsonElement` values with `.Clone()` if they must outlive the receiving iteration's
`JsonDocument`. Hyphenated JSON names such as `ip-address` can be mapped to DTO properties
with `System.Text.Json.Serialization.JsonPropertyNameAttribute`; preserve unmapped data when
forward-compatible storage matters. Handle unknown events explicitly before changing state.

Do not share the socket across application worker threads. The example polls at most 250 ms
at a time so Ctrl+C remains responsive, disposes its socket, and calls `NetMQConfig.Cleanup`
when exiting. In an application hosting other NetMQ sockets, coordinate global cleanup with
their owners rather than copying that process-wide cleanup into every consumer instance.

## Options and output

Run the DLL with `--help` to list options:

- `--endpoint ADDRESS`: publisher endpoint, default `tcp://127.0.0.1:5556`.
- `--topic PREFIX`: byte-prefix subscription, default `ip-audit.`. Pass an empty string to
  subscribe to everything, including empty topics.
- `--count NUMBER`: exit after this many accepted records; default `0` is unlimited.
- `--timeout-ms NUMBER`: idle timeout, default `30000`; `-1` waits indefinitely.
- `--receive-hwm NUMBER`: positive receive queue limit, default `1000`.
- `--schema PATH`: alternative audit schema; the default is the bundled file, not a path
  relative to the shell's working directory.
- `--strict-schema`: require exact producer-schema conformance rather than compatible reading.
- `--json` or `--table`: mutually exclusive alternatives to readable output.

Human output is a summary of topic, timestamp, event, address, address family and server.
JSON output is one complete `{"topic": ..., "record": ...}` envelope per accepted record,
preserving unknown fields; this wrapper belongs to the listener, not the hook's wire payload.
Table output uses the same stable TSV columns as the Python listener:
`topic`, `timestamp`, `event`, `ip-address`, `address-family`, `server`.
Missing optional values are empty; all other record fields are omitted from the table.
Tabs, newlines and quotes in cells use CSV-style quoting and must be read by a TSV parser.

Exit statuses are `0` for the requested record count or Ctrl+C, `1` for an idle timeout, and
`2` for invalid options, schema loading or socket errors. Invalid incoming records do not
count toward `--count` and do not change a later successful exit. An idle timeout is not
proof of connection failure; event filters, renewal policies or lack of traffic may explain it.
NetMQ reconnects to an available publisher, but missed messages are not replayed.

## Tests

From a source checkout, after installing the Python example requirements and building the
.NET project, run the shared consumer suite against the compiled DLL:

```sh
.venv/bin/python -B tests/test_consumer.py --dotnet-listener build/netmq/bin/AuditListener/release/AuditListener.dll
```

The optional .NET tests exercise all nine fixtures over real TCP, human/JSON/TSV output,
escaped TSV cells, compatible and strict validation, malformed messages, empty topics,
command-line errors, idle timeouts and publisher reconnects. Without `--dotnet-listener`,
the existing Python tests run and .NET tests are skipped. CI builds the project with the
.NET 10 SDK and runs both sets of tests. The listener also works with the fixture publisher's
burst, malformed-message and restart scenarios from the [integration guide](integration.md).