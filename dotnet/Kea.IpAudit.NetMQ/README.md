# Kea.IpAudit.NetMQ

A .NET 10 client for the Kea IP Audit hook's multipart JSON ZeroMQ stream, maintained by
Solvation. The .NET library is MIT licensed; this does not change the hook's licensing.

The client preserves complete records, validates the embedded producer schema, and supports
forward-compatible `1.x.y` reading. This is a best-effort notification stream, not a durable
queue or a live lease database. Retain a separate historical source and plan reconciliation.

## Getting started

Install from NuGet.org:

```sh
dotnet add package Kea.IpAudit.NetMQ
```

Configure the hook with multipart JSON and topic `ip-audit.%{event}`, then receive records:

```csharp
using Kea.IpAudit;

using var stopping = new CancellationTokenSource();
Console.CancelKeyPress += (_, arguments) =>
{
    arguments.Cancel = true;
    stopping.Cancel();
};

await using var client = new AuditClient(new AuditClientOptions
{
    Endpoint = "tcp://127.0.0.1:5556",
    TopicPrefix = "ip-audit.",
    BufferCapacity = 256
});

try
{
    await foreach (AuditMessage message in client.ReadAllAsync(stopping.Token))
    {
        if (message.Record.KnownEvent is null)
            continue;
        Console.WriteLine($"{message.Record.EventName} {message.Record.Address}");
    }
}
catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
```

Use `message.RawRecord` for the complete original JSON, including unknown fields.
Typed fields use the hook's JSON names; optional fields may be null, and DHCPv6 delegated
prefixes require both `Address` and `PrefixLength`. `KnownEvent` is null for future names:
do not silently assign them lease semantics. `AuditRecordDecoder` can validate archived
record frames without opening a socket.

## Behavior and configuration

- One enumeration may be active per client. The socket stays on a dedicated thread while
  `ReadAllAsync` uses a bounded decoded-record channel. A full buffer pauses receiving and
  can cause upstream PUB/SUB loss; it is not a durable spool.
- Cancellation, breaking enumeration, `Dispose` and `DisposeAsync` close only this client's
  resources and discard pending records. The library never calls global NetMQ cleanup.
- `ValidationMode = AuditValidationMode.Exact` pins the embedded `1.0.0` schema. Compatible
  reading accepts `1.x.y`, validates known fields and preserves unknown data.
- Invalid messages are skipped by default and counted. Set `InvalidMessageHandling` to
  `AuditInvalidMessageHandling.Throw` to stop the stream with `AuditRecordException`.
- An optional `ILogger<AuditClient>` constructor argument receives rejection reasons without
  payloads. `Diagnostics` reports cumulative received, buffered, rejected and unknown-event
  counts plus the last rejection reason; it cannot count PUB drops or prove completeness.
- `IdleTimeout` is null by default. When configured it ends an idle receive stream with
  `AuditIdleTimeoutException`, not proof of a connection failure.
- `ReceiveHighWatermark`, `BufferCapacity`, and `MaximumMessageBytes` bound local queues
  and decoding work. The decoding size limit does not prevent prior network allocations.
- NetMQ does not supply authentication, encryption, acknowledgement or replay here. Use
  protected TCP endpoints; do not assume native ZeroMQ IPC transports work with NetMQ.

Package versions are independent of audit schema versions. The initial API is version
`0.1.0`; applications should pin versions and review changes before upgrading.

See the [developer guides](https://github.com/solvationab/KeaLogHook/tree/main/docs/developer)
for the console example, fixtures, wire format and recovery.
