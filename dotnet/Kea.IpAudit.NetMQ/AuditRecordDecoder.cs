using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

namespace Kea.IpAudit;

/// <summary>Chooses exact producer conformance or supported-major-version reading.</summary>
public enum AuditValidationMode
{
    /// <summary>Accept 1.x.y, preserve unknown fields, and retain unknown event names.</summary>
    Compatible,
    /// <summary>Require the exact version, properties and events in the producer schema.</summary>
    Exact
}

/// <summary>A safe rejection reason without the original personal record contents.</summary>
public sealed class AuditRecordException(string message) : IOException(message);

/// <summary>Validates multipart audit JSON and maps it to typed records.</summary>
public sealed class AuditRecordDecoder
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly JsonSchema schema;

    /// <summary>Creates a decoder using the embedded schema, or explicitly supplied audit schema JSON.</summary>
    public AuditRecordDecoder(AuditValidationMode mode = AuditValidationMode.Compatible, string? schemaJson = null)
    {
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));
        if (schemaJson is null)
        {
            using Stream stream = typeof(AuditRecordDecoder).Assembly.GetManifestResourceStream(
                "Kea.IpAudit.audit-record.schema.json") ?? throw new InvalidOperationException("Embedded schema is missing");
            using var reader = new StreamReader(stream);
            schemaJson = reader.ReadToEnd();
        }
        JsonObject definition = JsonNode.Parse(schemaJson) as JsonObject
            ?? throw new ArgumentException("Audit schema must be an object", nameof(schemaJson));
        if (mode == AuditValidationMode.Compatible)
        {
            JsonObject properties = definition["properties"] as JsonObject
                ?? throw new ArgumentException("Audit schema must define properties", nameof(schemaJson));
            definition["additionalProperties"] = true;
            properties["schema-version"] = JsonNode.Parse(
                """{"type":"string","pattern":"^1\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"}""");
            properties["event"] = JsonNode.Parse("""{"type":"string","minLength":1}""");
        }
        schema = JsonSchema.Build(JsonSerializer.SerializeToElement(definition),
            new BuildOptions { Dialect = Dialect.Draft202012, SchemaRegistry = new() });
    }

    /// <summary>Decodes exactly two frames: a topic and a JSON record.</summary>
    public AuditMessage Decode(IReadOnlyList<byte[]> frames)
    {
        ArgumentNullException.ThrowIfNull(frames);
        if (frames.Count != 2 || frames[0] is null || frames[1] is null)
            throw new AuditRecordException("expected exactly two frames: topic and JSON payload");
        return Decode(frames[0], frames[1]);
    }

    /// <summary>Decodes strict UTF-8 and returns data independent of the input buffers.</summary>
    public AuditMessage Decode(ReadOnlySpan<byte> topicBytes, ReadOnlySpan<byte> payloadBytes)
    {
        try
        {
            string topic = StrictUtf8.GetString(topicBytes);
            using JsonDocument document = JsonDocument.Parse(StrictUtf8.GetString(payloadBytes));
            RejectDuplicateKeys(document.RootElement);
            if (!schema.Evaluate(document.RootElement,
                    new EvaluationOptions { RequireFormatValidation = true }).IsValid)
                throw new AuditRecordException("record does not match the selected schema");
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("ip-address", out JsonElement address)
                || address.ValueKind != JsonValueKind.String
                || !IPAddress.TryParse(address.GetString(), out _))
                throw new AuditRecordException("invalid ip-address");
            AuditRecord record = document.RootElement.Deserialize<AuditRecord>()
                ?? throw new AuditRecordException("record must be an object");
            return new AuditMessage(topic, record, document.RootElement.Clone());
        }
        catch (DecoderFallbackException)
        {
            throw new AuditRecordException("invalid UTF-8 payload or topic");
        }
        catch (JsonException)
        {
            throw new AuditRecordException("invalid JSON or typed record values");
        }
    }

    private static void RejectDuplicateKeys(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new AuditRecordException("duplicate JSON key");
                RejectDuplicateKeys(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray()) RejectDuplicateKeys(item);
        }
    }
}