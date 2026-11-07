using System.Text;
using System.Text.Json.Nodes;
using Kea.IpAudit;

byte[] payload = Encoding.UTF8.GetBytes("""
    {"timestamp":"2026-11-07T12:00:00.123Z","event":"lease-assign","schema-version":"1.0.0","ip-address":"192.0.2.10"}
    """);
AuditMessage exact = new AuditRecordDecoder(AuditValidationMode.Exact).Decode("ip-audit.lease-assign"u8, payload);
if (exact.Record.KnownEvent != AuditEvent.Assign || exact.Record.Address.ToString() != "192.0.2.10")
    throw new InvalidOperationException("Packaged decoder returned unexpected typed data");
JsonNode future = JsonNode.Parse(payload)!;
future["schema-version"] = "1.1.0";
future["event"] = "future-event";
future["future-field"] = "retained";
AuditMessage compatible = new AuditRecordDecoder().Decode([], Encoding.UTF8.GetBytes(future.ToJsonString()));
if (compatible.Record.KnownEvent is not null
    || compatible.RawRecord.GetProperty("future-field").GetString() != "retained")
    throw new InvalidOperationException("Packaged compatible reader lost future data");
await using var client = new AuditClient(new AuditClientOptions
{
    Endpoint = "tcp://127.0.0.1:1", IdleTimeout = TimeSpan.FromMilliseconds(10)
});
await using var stream = client.ReadAllAsync().GetAsyncEnumerator();
try
{
    await stream.MoveNextAsync();
    throw new InvalidOperationException("Packaged client did not enforce its idle timeout");
}
catch (AuditIdleTimeoutException) { }
Console.WriteLine("NuGet package smoke checks passed.");