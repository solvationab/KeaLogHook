using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Kea.IpAudit;
using Microsoft.Extensions.Logging;
using NetMQ;
using NetMQ.Sockets;
using Xunit;

namespace Kea.IpAudit.Tests;

public sealed class AuditClientTests
{
    private static IAsyncEnumerator<AuditMessage> Enumerate(AuditClient client, CancellationToken? token = null)
        => client.ReadAllAsync(token ?? TestContext.Current.CancellationToken)
            .GetAsyncEnumerator(TestContext.Current.CancellationToken);

    private static Task<T> Wait<T>(Task<T> task, int seconds = 5)
        => task.WaitAsync(TimeSpan.FromSeconds(seconds), TestContext.Current.CancellationToken);

    private static Task Wait(Task task, int seconds = 5)
        => task.WaitAsync(TimeSpan.FromSeconds(seconds), TestContext.Current.CancellationToken);

    private static byte[] Payload => Encoding.UTF8.GetBytes(File.ReadLines(
        Path.Combine(AppContext.BaseDirectory, "records.jsonl")).First());

    private static byte[] Change(string property, JsonNode? value)
    {
        JsonNode record = JsonNode.Parse(Payload)!;
        record[property] = value;
        return Encoding.UTF8.GetBytes(record.ToJsonString());
    }

    [Fact]
    public void EmbeddedSchemaAndTypedFixturesWorkWithoutSourceTree()
    {
        var decoder = new AuditRecordDecoder(AuditValidationMode.Exact);
        var events = new HashSet<AuditEvent?>();
        var leases = new HashSet<string?>();
        foreach (string line in File.ReadLines(Path.Combine(AppContext.BaseDirectory, "records.jsonl")))
        {
            AuditMessage message = decoder.Decode([], Encoding.UTF8.GetBytes(line));
            events.Add(message.Record.KnownEvent);
            leases.Add(message.Record.LeaseType);
            Assert.Equal("1.0.0", message.Record.SchemaVersion);
            Assert.NotNull(message.Record.Address);
            Assert.Equal(message.Record.IpAddress, message.RawRecord.GetProperty("ip-address").GetString());
        }
        Assert.Equal(6, events.Count);
        Assert.Contains("IA_PD", leases);
        Assert.Contains("IA_TA", leases);
        Assert.Contains("IA_NA", leases);
    }

    [Fact]
    public void CompatibleReaderPreservesFutureEventsAndIndependentRawJson()
    {
        JsonNode record = JsonNode.Parse(Payload)!;
        record["schema-version"] = "1.2.0";
        record["event"] = "future-event";
        record["future-field"] = JsonNode.Parse("""{"nested":"value"}""");
        byte[] input = Encoding.UTF8.GetBytes(record.ToJsonString());
        AuditMessage message = new AuditRecordDecoder().Decode("topic"u8, input);
        Array.Clear(input);
        Assert.Null(message.Record.KnownEvent);
        Assert.Equal("value", message.Record.AdditionalFields!["future-field"].GetProperty("nested").GetString());
        Assert.Equal("1.2.0", message.RawRecord.GetProperty("schema-version").GetString());
        Assert.Throws<AuditRecordException>(() => new AuditRecordDecoder(AuditValidationMode.Exact)
            .Decode([], Encoding.UTF8.GetBytes(record.ToJsonString())));
    }

    [Theory]
    [InlineData("schema-version", "2.0.0")]
    [InlineData("schema-version", "1.01.0")]
    [InlineData("timestamp", "yesterday")]
    [InlineData("ip-address", "not-an-ip")]
    [InlineData("subnet-id", "1")]
    [InlineData("event", "")]
    public void InvalidKnownFieldsAreRejected(string property, string value)
    {
        byte[] input = Change(property, JsonValue.Create(value));
        Assert.Throws<AuditRecordException>(() => new AuditRecordDecoder().Decode([], input));
    }

    [Theory]
    [InlineData("{broken")]
    [InlineData("[]")]
    [InlineData("{\"event\":\"a\",\"event\":\"b\"}")]
    [InlineData("{\"future\":NaN}")]
    public void InvalidJsonIsRejectedWithoutEchoingPayload(string text)
    {
        AuditRecordException error = Assert.Throws<AuditRecordException>(() =>
            new AuditRecordDecoder().Decode([], Encoding.UTF8.GetBytes(text)));
        Assert.DoesNotContain(text, error.Message);
    }

    [Fact]
    public void FramesEncodingAndRequiredFieldsAreChecked()
    {
        var decoder = new AuditRecordDecoder();
        Assert.Throws<AuditRecordException>(() => decoder.Decode(new byte[][] { Payload }));
        Assert.Throws<AuditRecordException>(() => decoder.Decode(new byte[][] { [], Payload, [] }));
        Assert.Throws<AuditRecordException>(() => decoder.Decode(new byte[] { 255 }, Payload));
        Assert.Throws<AuditRecordException>(() => decoder.Decode([], new byte[] { 255 }));
        JsonNode record = JsonNode.Parse(Payload)!;
        record.AsObject().Remove("schema-version");
        Assert.Throws<AuditRecordException>(() => decoder.Decode([], Encoding.UTF8.GetBytes(record.ToJsonString())));
    }

    [Fact]
    public void OptionsAndAlternateSchemasAreValidated()
    {
        foreach (AuditClientOptions options in new[]
        {
            new AuditClientOptions { Endpoint = "" }, new AuditClientOptions { BufferCapacity = 0 },
            new AuditClientOptions { ReceiveHighWatermark = 0 }, new AuditClientOptions { MaximumMessageBytes = 0 },
            new AuditClientOptions { IdleTimeout = TimeSpan.FromMilliseconds(-1) },
            new AuditClientOptions { ValidationMode = (AuditValidationMode)99 },
            new AuditClientOptions { InvalidMessageHandling = (AuditInvalidMessageHandling)99 }
        }) Assert.ThrowsAny<ArgumentException>(() => new AuditClient(options));
        Assert.Throws<ArgumentException>(() => new AuditRecordDecoder(schemaJson: "[]"));
        Assert.Throws<ArgumentException>(() => new AuditRecordDecoder(schemaJson: "{}"));
    }

    [Fact]
    public async Task IdleTimeoutAndPrecancelledEnumerationAreBounded()
    {
        await using var client = new AuditClient(new AuditClientOptions
        {
            Endpoint = "tcp://127.0.0.1:1", IdleTimeout = TimeSpan.FromMilliseconds(20)
        });
        await using var enumerator = Enumerate(client);
        await Assert.ThrowsAsync<AuditIdleTimeoutException>(async () => await enumerator.MoveNextAsync());
        await using var cancelledClient = new AuditClient();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await using var stopped = Enumerate(cancelledClient, cancelled.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await stopped.MoveNextAsync());
    }

    [Fact]
    public async Task RejectionsUnknownEventsLoggingAndCountersAreObservable()
    {
        using var publisher = new TestPublisher();
        var logger = new TestLogger();
        await using var client = new AuditClient(new AuditClientOptions { Endpoint = publisher.Endpoint }, logger);
        await using var stream = Enumerate(client);
        Task<bool> next = stream.MoveNextAsync().AsTask();
        publisher.Send("ip-audit.test", Encoding.UTF8.GetBytes("{sensitive-invalid-data"));
        publisher.Send("ip-audit.test", Change("event", JsonValue.Create("future-event")));
        Assert.True(await Wait(next));
        Assert.Null(stream.Current.Record.KnownEvent);
        Assert.Equal(2, client.Diagnostics.ReceivedMessages);
        Assert.Equal(1, client.Diagnostics.RejectedMessages);
        Assert.Equal(1, client.Diagnostics.UnknownEvents);
        Assert.NotNull(client.Diagnostics.LastRejectionReason);
        Assert.Contains(logger.Messages, text => text.Contains("Rejected audit message"));
        Assert.DoesNotContain(logger.Messages, text => text.Contains("sensitive-invalid-data"));
    }

    [Fact]
    public async Task ThrowPolicyAndDecodingSizeLimitAreEnforced()
    {
        using var publisher = new TestPublisher();
        await using var failClient = new AuditClient(new AuditClientOptions
        {
            Endpoint = publisher.Endpoint, TopicPrefix = "fail.", InvalidMessageHandling = AuditInvalidMessageHandling.Throw
        });
        await using var failStream = Enumerate(failClient);
        Task<bool> failure = failStream.MoveNextAsync().AsTask();
        publisher.Send("fail.test", "{broken"u8.ToArray(), "fail.");
        await Assert.ThrowsAsync<AuditRecordException>(async () => await Wait(failure));
        await using var client = new AuditClient(new AuditClientOptions
        {
            Endpoint = publisher.Endpoint, MaximumMessageBytes = 1024
        });
        await using var stream = Enumerate(client);
        Task<bool> next = stream.MoveNextAsync().AsTask();
        publisher.Send("ip-audit.test", new byte[2048]);
        publisher.Send("ip-audit.test", Payload);
        Assert.True(await Wait(next));
        Assert.Equal(1, client.Diagnostics.RejectedMessages);
        Assert.Contains("size limit", client.Diagnostics.LastRejectionReason!);
    }

    [Fact]
    public async Task DisposalUnblocksFullBufferAndRejectsFurtherEnumeration()
    {
        using var publisher = new TestPublisher();
        var client = new AuditClient(new AuditClientOptions { Endpoint = publisher.Endpoint, BufferCapacity = 1 });
        await using var stream = Enumerate(client);
        Task<bool> next = stream.MoveNextAsync().AsTask();
        publisher.Send("ip-audit.test", Payload);
        Assert.True(await Wait(next));
        for (int index = 0; index < 5; index++) publisher.Send("ip-audit.test", Payload);
        Assert.True(SpinWait.SpinUntil(() => client.Diagnostics.ReceivedMessages >= 3, TimeSpan.FromSeconds(5)));
        await Wait(client.DisposeAsync().AsTask(), 2);
        client.Dispose();
        await using var afterDisposal = Enumerate(client);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await afterDisposal.MoveNextAsync());
    }

    [Fact]
    public async Task DisposingOneClientDoesNotStopAnotherClient()
    {
        using var publisher = new TestPublisher();
        await using var first = new AuditClient(new AuditClientOptions { Endpoint = publisher.Endpoint, TopicPrefix = "first." });
        await using var second = new AuditClient(new AuditClientOptions { Endpoint = publisher.Endpoint, TopicPrefix = "second." });
        await using var firstStream = Enumerate(first);
        await using var secondStream = Enumerate(second);
        Task<bool> firstNext = firstStream.MoveNextAsync().AsTask();
        Task<bool> secondNext = secondStream.MoveNextAsync().AsTask();
        publisher.Send("first.test", Payload, "first.");
        Assert.True(await Wait(firstNext));
        await first.DisposeAsync();
        publisher.Send("second.test", Payload, "second.");
        Assert.True(await Wait(secondNext));
        Assert.Equal("second.test", secondStream.Current.Topic);
    }

    [Fact]
    public async Task ConcurrentEnumerationsAreRejectedAndCancellationStopsTheOwner()
    {
        await using var client = new AuditClient();
        using var cancellation = new CancellationTokenSource();
        await using var first = Enumerate(client, cancellation.Token);
        Task<bool> pending = first.MoveNextAsync().AsTask();
        await using var second = Enumerate(client);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await second.MoveNextAsync());
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Wait(pending, 2));
    }

    private sealed class TestLogger : ILogger<AuditClient>
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error,
            Func<TState, Exception?, string> formatter) => Messages.Enqueue(formatter(state, error));
    }

    private sealed class TestPublisher : IDisposable
    {
        private readonly CancellationTokenSource stop = new();
        private readonly BlockingCollection<byte[][]> messages = new();
        private readonly ConcurrentDictionary<string, ManualResetEventSlim> subscriptions = new();
        private readonly TaskCompletionSource<string> endpoint = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Thread worker;
        public string Endpoint => endpoint.Task.GetAwaiter().GetResult();

        public TestPublisher()
        {
            worker = new Thread(Run) { IsBackground = true };
            worker.Start();
            _ = Wait(endpoint.Task).GetAwaiter().GetResult();
        }

        public void Send(string topic, byte[] payload, string prefix = "ip-audit.")
        {
            Assert.True(subscriptions.GetOrAdd(prefix, _ => new ManualResetEventSlim())
                .Wait(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken),
                "Subscriber did not establish its subscription");
            messages.Add([Encoding.UTF8.GetBytes(topic), payload], TestContext.Current.CancellationToken);
        }

        private void Run()
        {
            try
            {
                using var socket = new XPublisherSocket();
                socket.Options.Linger = TimeSpan.Zero;
                int port = socket.BindRandomPort("tcp://127.0.0.1");
                endpoint.SetResult($"tcp://127.0.0.1:{port}");
                while (!stop.IsCancellationRequested)
                {
                    if (socket.TryReceiveFrameBytes(TimeSpan.FromMilliseconds(10), out byte[]? notification)
                        && notification.Length > 0 && notification[0] == 1)
                        subscriptions.GetOrAdd(Encoding.UTF8.GetString(notification, 1, notification.Length - 1),
                            _ => new ManualResetEventSlim()).Set();
                    if (messages.TryTake(out byte[][]? parts)) socket.SendMultipartBytes(parts);
                }
            }
            catch (Exception error) { endpoint.TrySetException(error); }
        }

        public void Dispose()
        {
            stop.Cancel();
            Assert.True(worker.Join(TimeSpan.FromSeconds(2)));
            stop.Dispose();
            messages.Dispose();
            foreach (ManualResetEventSlim subscription in subscriptions.Values) subscription.Dispose();
        }
    }
}