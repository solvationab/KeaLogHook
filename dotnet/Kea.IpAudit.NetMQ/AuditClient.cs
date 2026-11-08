using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetMQ;
using NetMQ.Sockets;

namespace Kea.IpAudit;

/// <summary>A single-consumer async stream whose NetMQ socket stays on its dedicated owner thread.</summary>
public sealed class AuditClient : IDisposable, IAsyncDisposable
{
    private readonly object gate = new();
    private readonly CancellationTokenSource lifetime = new();
    private readonly AuditClientOptions options;
    private readonly AuditRecordDecoder decoder;
    private readonly ILogger<AuditClient> logger;
    private TaskCompletionSource? completion;
    private bool active;
    private bool disposed;
    private bool lifetimeDisposed;
    private long received;
    private long buffered;
    private long rejected;
    private long unknown;
    private string? lastRejection;

    /// <summary>Validates configuration and schema. The socket opens when enumeration starts.</summary>
    public AuditClient(AuditClientOptions? options = null, ILogger<AuditClient>? logger = null)
    {
        this.options = options ?? new AuditClientOptions();
        if (string.IsNullOrWhiteSpace(this.options.Endpoint))
            throw new ArgumentException("Endpoint must not be empty", nameof(options));
        ArgumentNullException.ThrowIfNull(this.options.TopicPrefix);
        if (this.options.ReceiveHighWatermark < 1 || this.options.BufferCapacity < 1
            || this.options.MaximumMessageBytes < 1 || this.options.IdleTimeout < TimeSpan.Zero
            || !Enum.IsDefined(this.options.InvalidMessageHandling))
            throw new ArgumentException("Queue limits and message size must be positive; idle timeout must be nonnegative", nameof(options));
        _ = new UTF8Encoding(false, true).GetBytes(this.options.TopicPrefix);
        decoder = new AuditRecordDecoder(this.options.ValidationMode, this.options.SchemaJson);
        this.logger = logger ?? NullLogger<AuditClient>.Instance;
    }

    /// <summary>Returns atomic cumulative counters for this client. Buffered records may still be unprocessed.</summary>
    public AuditClientDiagnostics Diagnostics => new(Interlocked.Read(ref received), Interlocked.Read(ref buffered),
        Interlocked.Read(ref rejected), Interlocked.Read(ref unknown), Volatile.Read(ref lastRejection));

    /// <summary>Reads until cancellation, disposal, a fatal error, or the optional idle timeout.</summary>
    /// <remarks>Only one enumeration may be active. Breaking enumeration shuts down its socket and discards pending records.</remarks>
    public async IAsyncEnumerable<AuditMessage> ReadAllAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        Channel<AuditMessage> channel;
        CancellationTokenSource linked;
        TaskCompletionSource finished;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (active) throw new InvalidOperationException("Only one audit enumeration may be active");
            cancellationToken.ThrowIfCancellationRequested();
            linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
            channel = Channel.CreateBounded<AuditMessage>(new BoundedChannelOptions(options.BufferCapacity)
            {
                SingleWriter = true, SingleReader = true, FullMode = BoundedChannelFullMode.Wait
            });
            finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            completion = finished;
            active = true;
            var worker = new Thread(() => Receive(channel.Writer, linked.Token, finished))
            {
                IsBackground = true, Name = "Kea IP Audit receive"
            };
            worker.Start();
        }
        try
        {
            await foreach (AuditMessage message in channel.Reader.ReadAllAsync(linked.Token).ConfigureAwait(false))
                yield return message;
        }
        finally
        {
            linked.Cancel();
            await finished.Task.ConfigureAwait(false);
            linked.Dispose();
            lock (gate) active = false;
        }
    }

    private void Receive(ChannelWriter<AuditMessage> writer, CancellationToken cancellationToken, TaskCompletionSource finished)
    {
        Exception? failure = null;
        try
        {
            using var socket = new SubscriberSocket();
            socket.Options.Linger = TimeSpan.Zero;
            socket.Options.ReceiveHighWatermark = options.ReceiveHighWatermark;
            socket.Subscribe(new UTF8Encoding(false, true).GetBytes(options.TopicPrefix));
            socket.Connect(options.Endpoint);
            var idle = Stopwatch.StartNew();
            var frames = new List<byte[]>(2);
            while (!cancellationToken.IsCancellationRequested)
            {
                double remaining = options.IdleTimeout is TimeSpan timeout
                    ? Math.Max(0, timeout.TotalMilliseconds - idle.Elapsed.TotalMilliseconds) : 100;
                int pollMilliseconds = (int)Math.Ceiling(Math.Min(100, remaining));
                if (!socket.TryReceiveMultipartBytes(TimeSpan.FromMilliseconds(pollMilliseconds), ref frames))
                {
                    if (options.IdleTimeout is TimeSpan limit && idle.Elapsed >= limit
                        && !cancellationToken.IsCancellationRequested)
                        throw new AuditIdleTimeoutException();
                    continue;
                }
                Interlocked.Increment(ref received);
                idle.Restart();
                AuditMessage message;
                try
                {
                    if (frames.Sum(frame => (long)frame.Length) > options.MaximumMessageBytes)
                        throw new AuditRecordException("message exceeds the configured decoding size limit");
                    message = decoder.Decode(frames);
                }
                catch (AuditRecordException error)
                {
                    Interlocked.Increment(ref rejected);
                    Volatile.Write(ref lastRejection, error.Message);
                    logger.LogWarning("Rejected audit message: {Reason}", error.Message);
                    if (options.InvalidMessageHandling == AuditInvalidMessageHandling.Throw) throw;
                    continue;
                }
                if (message.Record.KnownEvent is null)
                {
                    Interlocked.Increment(ref unknown);
                    logger.LogDebug("Unknown audit event retained without lease semantics");
                }
                writer.WriteAsync(message, cancellationToken).AsTask().GetAwaiter().GetResult();
                Interlocked.Increment(ref buffered);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception error) { failure = error; }
        finally
        {
            writer.TryComplete(failure);
            finished.TrySetResult();
        }
    }

    private Task Stop()
    {
        lock (gate)
        {
            if (!disposed)
            {
                disposed = true;
                lifetime.Cancel();
            }
            return completion?.Task ?? Task.CompletedTask;
        }
    }

    private void DisposeLifetime()
    {
        lock (gate)
        {
            if (lifetimeDisposed) return;
            lifetime.Dispose();
            lifetimeDisposed = true;
        }
    }

    /// <summary>Stops receiving and waits for this client's socket to close. Does not perform global NetMQ cleanup.</summary>
    public void Dispose()
    {
        Stop().GetAwaiter().GetResult();
        DisposeLifetime();
    }

    /// <summary>Stops receiving asynchronously, closes only this client's resources, and discards its buffer.</summary>
    public async ValueTask DisposeAsync()
    {
        await Stop().ConfigureAwait(false);
        DisposeLifetime();
    }
}