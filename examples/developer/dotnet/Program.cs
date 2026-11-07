using System.Globalization;
using System.Text.Json;
using Kea.IpAudit;
using Microsoft.Extensions.Logging;
using Json.Schema;
using NetMQ;

internal enum OutputMode { Human, Json, Table }

internal sealed class ListenerOptions
{
    public string Endpoint { get; set; } = "tcp://127.0.0.1:5556";
    public string Topic { get; set; } = "ip-audit.";
    public string? SchemaPath { get; set; }
    public int Count { get; set; }
    public int TimeoutMs { get; set; } = 30000;
    public int ReceiveHwm { get; set; } = 1000;
    public bool StrictSchema { get; set; }
    public OutputMode Output { get; set; }
}

internal static class Program
{
    private static readonly string[] Columns =
        ["topic", "timestamp", "event", "ip-address", "address-family", "server"];

    public static async Task<int> Main(string[] arguments)
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
                    --schema PATH         Alternate audit JSON Schema (default: embedded)
                    --strict-schema       Require the exact published schema
                    --json | --table      Complete JSON envelopes or TSV summaries
                    --help                Show this help
                    """);
                return 0;
            }
            return await Run(ParseOptions(arguments));
        }
        catch (AuditIdleTimeoutException)
        {
            Console.Error.WriteLine("No record received before the idle timeout; check publisher and topic.");
            return 1;
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

    private static async Task<int> Run(ListenerOptions options)
    {
        using var cancelled = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancelled.Cancel();
        };
        Console.CancelKeyPress += onCancel;
        try
        {
            await using var client = new AuditClient(new AuditClientOptions
            {
                Endpoint = options.Endpoint,
                TopicPrefix = options.Topic,
                ReceiveHighWatermark = options.ReceiveHwm,
                IdleTimeout = options.TimeoutMs < 0 ? null : TimeSpan.FromMilliseconds(options.TimeoutMs),
                ValidationMode = options.StrictSchema ? AuditValidationMode.Exact : AuditValidationMode.Compatible,
                SchemaJson = options.SchemaPath is null ? null : File.ReadAllText(options.SchemaPath)
            }, new ConsoleAuditLogger());
            if (options.Output == OutputMode.Table)
                Console.WriteLine(string.Join('\t', Columns));
            int accepted = 0;
            await foreach (AuditMessage message in client.ReadAllAsync(cancelled.Token))
            {
                WriteRecord(options.Output, message.Topic, message.RawRecord);
                accepted++;
                if (options.Count > 0 && accepted >= options.Count) break;
            }
            return 0;
        }
        catch (OperationCanceledException) when (cancelled.IsCancellationRequested) { return 0; }
        finally
        {
            Console.CancelKeyPress -= onCancel;
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

    private sealed class ConsoleAuditLogger : ILogger<AuditClient>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Warning;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(level)) Console.Error.WriteLine(formatter(state, error).Replace("Rejected audit message:", "Rejected message:"));
        }
    }
}