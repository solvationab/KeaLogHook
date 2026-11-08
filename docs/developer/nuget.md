# .NET client package

`Kea.IpAudit.NetMQ` is the reusable .NET 10 client library. Its source and package README
are in [dotnet/Kea.IpAudit.NetMQ](../../dotnet/Kea.IpAudit.NetMQ/README.md). The library is
[MIT licensed](../../dotnet/Kea.IpAudit.NetMQ/LICENSE.md), published by Solvation; this
license applies to the new library, not the C++ hook or the repository as a whole.

## Application integration

After the initial package has been published to NuGet.org:

```sh
dotnet add package Kea.IpAudit.NetMQ --version 0.1.0
```

No custom feed or native libzmq installation is needed. Configure the hook's
[ZeroMQ example](../../examples/sink-zeromq.json), then use:

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
        Console.WriteLine($"{message.Record.Timestamp:O} {message.Record.EventName} {message.Record.Address}");
    }
}
catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
```

The console [NetMQ example](dotnet.md) now uses this library through a project reference.
Applications installed from NuGet.org use a package reference instead. NuGet carries the
NetMQ, JsonSchema.Net and logging-abstraction dependencies, XML API documentation, package
README, and MIT license. The producer schema is embedded in the assembly and requires no
external file or working-directory setup.

`AuditMessage` contains the actual topic, a typed `AuditRecord`, and independently owned
`RawRecord` JSON. Retain the raw JSON for full fidelity; serializing the typed model alone
may change timestamp formatting or represent absent fields differently. Unknown fields are
also available through `AdditionalFields`. Optional fields may be null, and IA_PD addresses
need their prefix length. An unknown event has `KnownEvent == null`; decide whether to retain
or quarantine it before applying state changes.

`AuditRecordDecoder` supports offline decoding of two record frames. The default compatible
mode accepts `1.x.y` and preserves unknown data. `AuditValidationMode.Exact` validates the
embedded `1.0.0` producer contract. Intentional field projections still need the four core
fields or an explicitly agreed alternate schema. See [Compatibility](compatibility.md).

## Lifetime and diagnostics

Only one enumeration may run per client. NetMQ receive operations remain on a dedicated
thread; application processing uses an async iterator with a bounded channel. Ending an
enumeration closes its socket, and a client may start a new enumeration afterward unless
disposed. Breaking enumeration, cancellation or disposal discards pending records. Dispose
or await-dispose clients you create. Disposing one client never invokes process-wide NetMQ
cleanup or shuts down another client.

An optional `ILogger<AuditClient>` constructor argument receives rejection reasons without
personal payload data. Invalid messages are skipped by default; the `Throw` policy ends the
stream with `AuditRecordException`. A configured idle timeout ends it with
`AuditIdleTimeoutException`; no timeout is configured by default. Socket/startup failures
propagate through enumeration. Cancellation raises `OperationCanceledException`.

Positive socket poll intervals are rounded up to whole milliseconds, with a 100 ms maximum
per poll. This avoids NetMQ's fractional-millisecond timeout trap; zero remains a nonblocking
check. Submillisecond idle timeouts therefore have millisecond polling granularity.

`Diagnostics` contains cumulative local counters: complete messages received from the socket,
records admitted to the decoded buffer, rejected messages, and validated unknown events,
plus the last rejection reason. Its fields are individually atomic, not a transactional
snapshot. Buffered records are not necessarily processed records or durable application commits.

`ReceiveHighWatermark` and `BufferCapacity` bound local queues. A full decoded buffer pauses
receiving; this may cause upstream PUB drops. `MaximumMessageBytes` limits decoding work after
the frames have arrived, not network allocation. Keep logging providers and application work
fast, and use a protected endpoint. There is no built-in authentication, replay, acknowledgement,
sequence number, stable event ID or exactly-once processing. Read [Recovery](recovery.md).

## Versioning and local validation

Package versions are independent of the audit schema version. The first client version is
`0.1.0`; release tags are `dotnet-vMAJOR.MINOR.PATCH`, separate from the hook's `v*` tags.
Before 1.0, pin the package and review API changes. After 1.0, use major versions for breaking
client APIs, minor for additive APIs, and patch for compatible fixes. Unsupported schema
majors remain a validation concern, not automatically supported by a new package version.

From a source checkout, using the .NET 10 SDK:

```sh
dotnet test --project dotnet/Kea.IpAudit.NetMQ.Tests/Kea.IpAudit.NetMQ.Tests.csproj --configuration Release --artifacts-path build/nuget
dotnet pack dotnet/Kea.IpAudit.NetMQ/Kea.IpAudit.NetMQ.csproj --configuration Release --artifacts-path build/nuget --output build/packages
dotnet run --project dotnet/Kea.IpAudit.NetMQ.PackageSmoke/Kea.IpAudit.NetMQ.PackageSmoke.csproj --configuration Release --artifacts-path build/nuget "-p:RestoreAdditionalProjectSources=$PWD/build/packages"
```

The smoke command uses an absolute additional-source path from the repository root. Use
`-p:AuditPackageVersion=VERSION` when testing a non-default package version, and an isolated
`-p:RestorePackagesPath=PATH` to avoid reusing a cached package while iterating on the same
version. The smoke project has no project reference: it checks the actual NuGet dependency
graph, embedded schema, typed models and receive lifecycle.

The root [global.json](../../global.json) selects .NET 10 and Microsoft Testing Platform.
The library tests cover rejection, buffering, cancellation, logging and independent client
lifetimes. The Python suite checks the wire contract, example and package metadata:

```sh
python -B tests/test_consumer.py --dotnet-listener build/nuget/bin/AuditListener/release/AuditListener.dll --nuget-package build/packages/Kea.IpAudit.NetMQ.0.1.0.nupkg
```

Build the example and install the [Python requirements](../../examples/developer/python/requirements.txt)
first. Package checks verify metadata, dependencies, license and XML API docs; SDK package
validation runs during packing. A `.snupkg` contains portable symbols with source information.

## NuGet.org publication setup

[.github/workflows/nuget.yml](../../.github/workflows/nuget.yml) builds and tests on Windows
and Ubuntu, packs both artifacts, validates a separately restored consumer, and saves CI
artifacts. Pull requests, main-branch pushes and manual dispatch validate only; publication
requires a `dotnet-v*` tag. Tags must be stable semantic versions without leading zeroes,
and their commit must already belong to `main`. CI candidate versions use `0.1.0-ci.RUN`.

Before the first release, the NuGet.org account owner must:

1. Sign in to the `Solvation` account, or use the appropriate member account if Solvation is
   an organization. Confirm rights to create `Kea.IpAudit.NetMQ` and publish future versions.
2. Create a GitHub environment named `nuget` with required reviewers and appropriate tag
    deployment restrictions. If the signing account differs from `Solvation`, update the
    workflow's NuGet login `user` value to its profile username, not an email address.
3. In NuGet.org **Trusted Publishing**, select the correct owner and register repository owner
   `solvationab`, repository `KeaLogHook`, workflow filename `nuget.yml` (not its full path),
   and environment `nuget`. Scope it only to `Kea.IpAudit.NetMQ`, allowing both new-package
   creation and new-version publication. Confirm that the policy is active.
4. Commit and review the library/workflow changes on main before creating and pushing the
   first release tag, for example `dotnet-v0.1.0`. Never reuse a published package version.

The protected publish job uses `NuGet/login@v1` to obtain a short-lived OIDC-derived key,
then pushes to `https://api.nuget.org/v3/index.json`. The adjacent `.snupkg` is pushed by
the NuGet client as part of publication. No long-lived secret is stored in the workflow.
`--skip-duplicate` permits a safe retry of an already published version; it does not replace
its contents. Verify both package visibility and symbols after the first successful release.

For an explicitly authorized manual first upload, a scoped API key may instead be set
directly in the terminal as `NUGET_API_KEY`; do not paste credentials into chat or commit
them. Push the validated package and matching symbols together. Manual upload does not
configure CI trusted publishing. Until account authorization or an active policy is available,
packing and testing alone do not mean that the package has been published.
