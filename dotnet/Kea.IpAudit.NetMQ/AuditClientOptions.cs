namespace Kea.IpAudit;

/// <summary>The response to an invalid incoming record.</summary>
public enum AuditInvalidMessageHandling
{
    /// <summary>Count and optionally log the rejection, then continue receiving.</summary>
    Skip,
    /// <summary>Stop the stream with an AuditRecordException.</summary>
    Throw
}

/// <summary>Immutable transport, buffering and validation configuration.</summary>
public sealed record AuditClientOptions
{
    /// <summary>The publisher endpoint; normally a protected TCP endpoint.</summary>
    public string Endpoint { get; init; } = "tcp://127.0.0.1:5556";
    /// <summary>A byte-prefix subscription; the empty string subscribes to everything.</summary>
    public string TopicPrefix { get; init; } = "ip-audit.";
    /// <summary>The positive NetMQ receive queue high-water mark.</summary>
    public int ReceiveHighWatermark { get; init; } = 1000;
    /// <summary>The positive decoded-record buffer capacity. A full buffer pauses receiving.</summary>
    public int BufferCapacity { get; init; } = 256;
    /// <summary>The maximum combined frame bytes to decode; not a network allocation limit.</summary>
    public int MaximumMessageBytes { get; init; } = 1048576;
    /// <summary>An optional idle timeout. Null waits until cancellation; zero checks without waiting.</summary>
    public TimeSpan? IdleTimeout { get; init; }
    /// <summary>The schema compatibility policy.</summary>
    public AuditValidationMode ValidationMode { get; init; } = AuditValidationMode.Compatible;
    /// <summary>The invalid-message policy.</summary>
    public AuditInvalidMessageHandling InvalidMessageHandling { get; init; } = AuditInvalidMessageHandling.Skip;
    /// <summary>Optional alternate audit schema JSON. Null uses the embedded producer schema.</summary>
    public string? SchemaJson { get; init; }
}

/// <summary>Cumulative local counters, not delivery guarantees or PUB drop counts.</summary>
public sealed record AuditClientDiagnostics(long ReceivedMessages, long BufferedRecords,
    long RejectedMessages, long UnknownEvents, string? LastRejectionReason);

/// <summary>The receive stream reached its configured idle timeout.</summary>
public sealed class AuditIdleTimeoutException() : TimeoutException("No audit record received before the idle timeout");