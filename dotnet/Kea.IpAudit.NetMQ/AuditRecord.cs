using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kea.IpAudit;

/// <summary>Known lease events. Unknown event names are retained separately.</summary>
public enum AuditEvent
{
    /// <summary>A new lease was committed.</summary>
    Assign,
    /// <summary>An existing lease was renewed or rebound.</summary>
    Renew,
    /// <summary>An old lease was deleted.</summary>
    Delete,
    /// <summary>The client released a lease.</summary>
    Release,
    /// <summary>The client declined a lease.</summary>
    Decline,
    /// <summary>The server reclaimed an expired lease.</summary>
    Expire
}

/// <summary>A schema-validated lease event with optional protocol-specific metadata.</summary>
public sealed record AuditRecord
{
    /// <summary>The event timestamp, including its UTC offset.</summary>
    [JsonPropertyName("timestamp")] public required DateTimeOffset Timestamp { get; init; }
    /// <summary>The original event name, including names unknown to this client.</summary>
    [JsonPropertyName("event")] public required string EventName { get; init; }
    /// <summary>The audit schema version, independent of the NuGet package version.</summary>
    [JsonPropertyName("schema-version")] public required string SchemaVersion { get; init; }
    /// <summary>The leased address or delegated network address.</summary>
    [JsonPropertyName("ip-address")] public required string IpAddress { get; init; }
    /// <summary>The hostname of the emitting server, not a process-instance identifier.</summary>
    [JsonPropertyName("server")] public string? Server { get; init; }
    /// <summary>The hardware address, when available.</summary>
    [JsonPropertyName("hw-address")] public string? HardwareAddress { get; init; }
    /// <summary>The DHCPv4 client identifier as colon-separated hex.</summary>
    [JsonPropertyName("client-id")] public string? ClientId { get; init; }
    /// <summary>The client hostname.</summary>
    [JsonPropertyName("hostname")] public string? Hostname { get; init; }
    /// <summary>The vendor class as hex.</summary>
    [JsonPropertyName("vendor-class")] public string? VendorClass { get; init; }
    /// <summary>The printable vendor class.</summary>
    [JsonPropertyName("vendor-class-text")] public string? VendorClassText { get; init; }
    /// <summary>The user class payload as hex.</summary>
    [JsonPropertyName("user-class")] public string? UserClass { get; init; }
    /// <summary>The Kea subnet identifier.</summary>
    [JsonPropertyName("subnet-id")] public long? SubnetId { get; init; }
    /// <summary>The configured POP label.</summary>
    [JsonPropertyName("pop")] public string? Pop { get; init; }
    /// <summary>The configured site label.</summary>
    [JsonPropertyName("site")] public string? Site { get; init; }
    /// <summary>The lease's valid lifetime, in seconds.</summary>
    [JsonPropertyName("valid-lifetime")] public long? ValidLifetime { get; init; }
    /// <summary>The lease expiry as emitted; null when absent or empty.</summary>
    [JsonIgnore] public DateTimeOffset? LeaseExpires => string.IsNullOrEmpty(LeaseExpiresText)
        ? null : DateTimeOffset.Parse(LeaseExpiresText, System.Globalization.CultureInfo.InvariantCulture);
    /// <summary>The original lease-expiry text; empty values are permitted by include-empty output.</summary>
    [JsonPropertyName("lease-expires")] public string? LeaseExpiresText { get; init; }
    /// <summary>The triggering DHCP message name.</summary>
    [JsonPropertyName("message-type")] public string? MessageType { get; init; }
    /// <summary>The DHCP transaction identifier as decimal text.</summary>
    [JsonPropertyName("transaction-id")] public string? TransactionId { get; init; }
    /// <summary>The receiving network interface.</summary>
    [JsonPropertyName("interface")] public string? Interface { get; init; }
    /// <summary>The DHCPv4 relay gateway address.</summary>
    [JsonPropertyName("giaddr")] public string? GatewayAddress { get; init; }
    /// <summary>The relay or packet peer address.</summary>
    [JsonPropertyName("relay-address")] public string? RelayAddress { get; init; }
    /// <summary>The circuit identifier as separator-free hex.</summary>
    [JsonPropertyName("circuit-id")] public string? CircuitId { get; init; }
    /// <summary>The escaped display form of the circuit identifier.</summary>
    [JsonPropertyName("circuit-id-text")] public string? CircuitIdText { get; init; }
    /// <summary>The remote identifier as hex.</summary>
    [JsonPropertyName("remote-id")] public string? RemoteId { get; init; }
    /// <summary>The escaped display form of the remote identifier.</summary>
    [JsonPropertyName("remote-id-text")] public string? RemoteIdText { get; init; }
    /// <summary>The subscriber identifier as hex.</summary>
    [JsonPropertyName("subscriber-id")] public string? SubscriberId { get; init; }
    /// <summary>The printable subscriber identifier.</summary>
    [JsonPropertyName("subscriber-id-text")] public string? SubscriberIdText { get; init; }
    /// <summary>The relay's DHCPv4 link-selection address.</summary>
    [JsonPropertyName("link-selection")] public string? LinkSelection { get; init; }
    /// <summary>The encoded relay suboptions.</summary>
    [JsonPropertyName("relay-suboptions")] public string? RelaySuboptions { get; init; }
    /// <summary>The relay flags as hex.</summary>
    [JsonPropertyName("relay-flags")] public string? RelayFlags { get; init; }
    /// <summary>The vendor-specific relay bytes as hex.</summary>
    [JsonPropertyName("relay-vendor-specific")] public string? RelayVendorSpecific { get; init; }
    /// <summary>IPv4 or IPv6, when present.</summary>
    [JsonPropertyName("address-family")] public string? AddressFamily { get; init; }
    /// <summary>The DHCPv6 lease type: IA_NA, IA_TA, or IA_PD.</summary>
    [JsonPropertyName("lease-type")] public string? LeaseType { get; init; }
    /// <summary>The identity association ID; interpret with DUID and lease type.</summary>
    [JsonPropertyName("iaid")] public long? Iaid { get; init; }
    /// <summary>The DHCPv6 DUID as colon-separated hex.</summary>
    [JsonPropertyName("duid")] public string? Duid { get; init; }
    /// <summary>The delegated prefix length, or null for host addresses.</summary>
    [JsonPropertyName("prefix-length")] public int? PrefixLength { get; init; }
    /// <summary>The DHCPv6 relay interface ID as hex.</summary>
    [JsonPropertyName("relay-interface-id")] public string? RelayInterfaceId { get; init; }
    /// <summary>The printable DHCPv6 relay interface ID.</summary>
    [JsonPropertyName("relay-interface-id-text")] public string? RelayInterfaceIdText { get; init; }
    /// <summary>The outermost DHCPv6 relay link address.</summary>
    [JsonPropertyName("relay-link-address")] public string? RelayLinkAddress { get; init; }
    /// <summary>Unknown fields retained for forward-compatible applications.</summary>
    [JsonExtensionData] public Dictionary<string, JsonElement>? AdditionalFields { get; init; }
    /// <summary>The parsed IP address; a delegated prefix still needs PrefixLength.</summary>
    [JsonIgnore] public IPAddress Address => IPAddress.Parse(IpAddress);
    /// <summary>The known event value, or null for a future event name.</summary>
    [JsonIgnore] public AuditEvent? KnownEvent => EventName switch
    {
        "lease-assign" => AuditEvent.Assign,
        "lease-renew" => AuditEvent.Renew,
        "lease-delete" => AuditEvent.Delete,
        "lease-release" => AuditEvent.Release,
        "lease-decline" => AuditEvent.Decline,
        "lease-expire" => AuditEvent.Expire,
        _ => null
    };
}

/// <summary>A received topic and independently owned record data.</summary>
public sealed record AuditMessage(string Topic, AuditRecord Record, JsonElement RawRecord);