using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;
using NetMQ;
using NetMQ.Sockets;

internal enum OutputMode { Human, Json, Table }

internal sealed class ListenerOptions
{
    public string Endpoint { get; set; } = "tcp://127.0.0.1:5556";
    public string Topic { get; set; } = "ip-audit.";
    public string SchemaPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "audit-record.schema.json");
    public int Count { get; set; }
    public int TimeoutMs { get; set; } = 30000;
    public int ReceiveHwm { get; set; } = 1000;
    public bool StrictSchema { get; set; }
    public OutputMode Output { get; set; }
}

internal static class Program
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] Columns =
        ["topic", "timestamp", "event", "ip-address", "address-family", "server"];

    public static int Main(string[] arguments)
    {
        try
        {
            if (arguments.Contains("--help"))
            {
                Console.WriteLine("""
                    NetMQ multipart JSON audit listener
                    --endpoint ADDRESS    Publisher endpoint (tcp://127.0.0.1:5556)
                    --topic PREFIX        Subscription prefix (ip-audit.); empty matches all
                    --count NUMBER        Accepted records before exit (0: unlimited)
                    --timeout-ms NUMBER   Idle timeout (30000; -1: indefinite)
                    --receive-hwm NUMBER  Receive queue high-water mark (1000)
                    --schema PATH         Audit JSON Schema (bundled beside executable)
                    --strict-schema       Require the exact published schema
                    --json | --table      Complete JSON envelopes or TSV summaries
                    --help                Show this help
                    """);
                return 0;
            }
            return Run(ParseOptions(arguments));
        }
        catch (Exception error) when (error is ArgumentException or IOException or JsonException
                                      or NetMQException or JsonSchemaException)
        {
            Console.Error.WriteLine($"Listener failed: {error.Message}");
            return 2;
        }
        finally
        {
            NetMQConfig.Cleanup(false);
        }
    }

    private static ListenerOptions ParseOptions(string[] arguments)
    {
        var options = new ListenerOptions();
        for (int index = 0; index < arguments.Length; index++)
        {
            switch (arguments[index])
            {
                case "--endpoint": options.Endpoint = NextValue(arguments, ref index); break;
                case "--topic": options.Topic = NextValue(arguments, ref index); break;
                case "--schema": options.SchemaPath = NextValue(arguments, ref index); break;
                case "--count": options.Count = NextNumber(arguments, ref index); break;
                case "--timeout-ms": options.TimeoutMs = NextNumber(arguments, ref index); break;
                case "--receive-hwm": options.ReceiveHwm = NextNumber(arguments, ref index); break;
                case "--strict-schema": options.StrictSchema = true; break;
                case "--json": SetOutput(options, OutputMode.Json); break;
                case "--table": SetOutput(options, OutputMode.Table); break;
                default: throw new ArgumentException($"Unknown option: {arguments[index]}");
            }
        }
        if (options.Count < 0 || options.TimeoutMs < -1 || options.ReceiveHwm < 1)
            throw new ArgumentException("count must be nonnegative, timeout-ms at least -1, and receive-hwm positive");
        return options;
    }

    private static string NextValue(string[] arguments, ref int index)
    {
        if (index + 1 >= arguments.Length)
            throw new ArgumentException($"Missing value for {arguments[index]}");
        return arguments[++index];
    }

    private static int NextNumber(string[] arguments, ref int index)
    {
        string value = NextValue(arguments, ref index);
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int number))
            throw new ArgumentException("Expected a 32-bit integer option value");
        return number;
    }

    private static void SetOutput(ListenerOptions options, OutputMode mode)
    {
        if (options.Output != OutputMode.Human && options.Output != mode)
            throw new ArgumentException("--json and --table are mutually exclusive");
        options.Output = mode;
    }

    private static JsonSchema LoadSchema(ListenerOptions options)
    {
        JsonNode schema = JsonNode.Parse(File.ReadAllText(options.SchemaPath))
            ?? throw new InvalidDataException("Schema must be a JSON object");
        if (!options.StrictSchema)
        {
            schema["additionalProperties"] = true;
            schema["properties"]!["schema-version"] = JsonNode.Parse(
                """{"type":"string","pattern":"^1\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"}""");
            schema["properties"]!["event"] = JsonNode.Parse("""{"type":"string","minLength":1}""");
        }
        return JsonSchema.Build(JsonSerializer.SerializeToElement(schema),
            new BuildOptions { Dialect = Dialect.Draft202012, SchemaRegistry = new() });
    }

    private static int Run(ListenerOptions options)
    {
        JsonSchema schema = LoadSchema(options);
        var evaluation = new EvaluationOptions { RequireFormatValidation = true };
        using var cancelled = new ManualResetEventSlim();
        ConsoleCancelEventHandler onCancel = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancelled.Set();
        };
        Console.CancelKeyPress += onCancel;
        try
        {
            using var socket = new SubscriberSocket();
            socket.Options.Linger = TimeSpan.Zero;
            socket.Options.ReceiveHighWatermark = options.ReceiveHwm;
            socket.Subscribe(StrictUtf8.GetBytes(options.Topic));
            socket.Connect(options.Endpoint);
            if (options.Output == OutputMode.Table)
                Console.WriteLine(string.Join('\t', Columns));
            var idle = Stopwatch.StartNew();
            int accepted = 0;
            while (!cancelled.IsSet && (options.Count == 0 || accepted < options.Count))
            {
                long remaining = options.TimeoutMs < 0 ? 250 : Math.Max(0, options.TimeoutMs - idle.ElapsedMilliseconds);
                var message = new NetMQMessage();
                if (!socket.TryReceiveMultipartMessage(TimeSpan.FromMilliseconds(Math.Min(250, remaining)), ref message))
                {
                    if (cancelled.IsSet) return 0;
                    if (options.TimeoutMs >= 0 && idle.ElapsedMilliseconds >= options.TimeoutMs)
                    {
                        Console.Error.WriteLine("No record received before the idle timeout; check publisher and topic.");
                        return 1;
                    }
                    continue;
                }
                idle.Restart();
                try
                {
                    if (message.FrameCount != 2)
                        throw new InvalidDataException("expected exactly two frames: topic and JSON payload");
                    string topic = StrictUtf8.GetString(message[0].ToByteArray());
                    using JsonDocument document = JsonDocument.Parse(StrictUtf8.GetString(message[1].ToByteArray()));
                    RejectDuplicateKeys(document.RootElement);
                    if (!schema.Evaluate(document.RootElement, evaluation).IsValid)
                        throw new InvalidDataException("record does not match the selected schema");
                    if (!IPAddress.TryParse(document.RootElement.GetProperty("ip-address").GetString(), out _))
                        throw new InvalidDataException("invalid ip-address");
                    WriteRecord(options.Output, topic, document.RootElement);
                    accepted++;
                }
                catch (Exception error) when (error is JsonException or DecoderFallbackException or InvalidDataException)
                {
                    Console.Error.WriteLine(error is InvalidDataException
                        ? $"Rejected message: {error.Message}" : "Rejected message: invalid UTF-8 or JSON payload");
                }
            }
            return 0;
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }
    }

    private static void RejectDuplicateKeys(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidDataException("duplicate JSON key");
                RejectDuplicateKeys(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
                RejectDuplicateKeys(item);
        }
    }

    private static void WriteRecord(OutputMode mode, string topic, JsonElement record)
    {
        if (mode == OutputMode.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { topic, record }));
            return;
        }
        string[] values = [topic, .. Columns.Skip(1).Select(name => record.TryGetProperty(name, out var value)
            ? value.GetString() ?? "" : mode == OutputMode.Table ? "" : "-")];
        Console.WriteLine(mode == OutputMode.Table
            ? string.Join('\t', values.Select(QuoteTsv))
            : string.Join(" | ", values.Select(value => new string(value.Select(character =>
                char.IsControl(character) ? '?' : character).ToArray()))));
    }

    private static string QuoteTsv(string value) => value.IndexOfAny(['\t', '\r', '\n', '"']) >= 0
        ? '"' + value.Replace("\"", "\"\"") + '"' : value;
}