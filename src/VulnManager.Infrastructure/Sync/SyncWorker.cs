using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Options;
using VulnManager.Application.Services;
using VulnManager.Application.Sync;
using VulnManager.Domain.Entities;

namespace VulnManager.Infrastructure.Sync;

/// <summary>Bounded in-memory channel; requests beyond capacity are dropped (the next scheduled tick catches up).</summary>
public sealed class SyncDispatcher : ISyncDispatcher
{
    private readonly Channel<SyncRequest> _channel = Channel.CreateBounded<SyncRequest>(new BoundedChannelOptions(100)
    {
        FullMode = BoundedChannelFullMode.DropWrite,
        SingleReader = true,
    });

    public ChannelReader<SyncRequest> Reader => _channel.Reader;

    public bool TryEnqueue(SyncRequest request) => _channel.Writer.TryWrite(request);
}

/// <summary>
/// Scheduled synchronization. A timer enqueues "due check" requests; a single consumer runs them sequentially, so jobs of
/// one instance never overlap (the partial unique index on sync_runs covers multiple instances). On Render free the
/// process sleeps after 15 minutes without traffic; a GitHub Actions cron calls the external trigger to wake it up.
/// </summary>
public sealed partial class SyncWorker(
    SyncDispatcher dispatcher,
    SyncRunner runner,
    IServiceScopeFactory scopes,
    TimeProvider time,
    IOptions<SyncOptions> options,
    ILogger<SyncWorker> logger) : BackgroundService
{
    private DateTimeOffset _lastPurge = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled)
        {
            LogDisabled(logger);
            return;
        }

        await Task.Yield();
        await SafeAsync(() => runner.RecoverStaleRunsAsync(stoppingToken), "recover stale runs");
        dispatcher.TryEnqueue(new SyncRequest(null, SyncTrigger.Startup));

        var ticker = TickAsync(stoppingToken);
        await foreach (var request in dispatcher.Reader.ReadAllAsync(stoppingToken))
        {
            await SafeAsync(() => ProcessAsync(request, stoppingToken), $"sync {request.Source?.ToString() ?? "due"}");
        }

        await ticker;
    }

    private async Task ProcessAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        if (request.Source is null && request.Trigger is SyncTrigger.Scheduled or SyncTrigger.Startup)
        {
            var due = await DueSourcesAsync(cancellationToken);
            foreach (var source in due)
            {
                await runner.RunAsync(request with { Source = source }, cancellationToken);
            }

            await PurgeAuditIfDueAsync(cancellationToken);
            return;
        }

        await runner.RunAsync(request, cancellationToken);
    }

    private async Task<IReadOnlyList<SyncSource>> DueSourcesAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var runs = scope.ServiceProvider.GetRequiredService<ISyncRunRepository>();
        var last = new Dictionary<SyncSource, DateTimeOffset?>();
        foreach (var source in SyncRunner.FullOrder)
        {
            last[source] = (await runs.LatestSuccessfulAsync(source, cancellationToken))?.StartedAt;
        }

        return SyncSchedulePolicy.DueSources(time.GetUtcNow(), last, options.Value);
    }

    private async Task PurgeAuditIfDueAsync(CancellationToken cancellationToken)
    {
        if (time.GetUtcNow() - _lastPurge < TimeSpan.FromDays(1))
        {
            return;
        }

        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AuditService>().PurgeExpiredAsync(cancellationToken);
        _lastPurge = time.GetUtcNow();
    }

    private async Task TickAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(options.Value.TickMinutes), time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                dispatcher.TryEnqueue(new SyncRequest(null, SyncTrigger.Scheduled));
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    private async Task SafeAsync(Func<Task> action, string operation)
    {
        try
        {
            await action();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
#pragma warning disable CA1031 // The worker must survive any failure of a single sync iteration.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogIterationFailed(logger, ex, operation);
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Scheduled synchronization is disabled (Sync:Enabled=false)")]
    private static partial void LogDisabled(ILogger logger);

    [LoggerMessage(Level = LogLevel.Error, Message = "Sync worker iteration failed: {Operation}")]
    private static partial void LogIterationFailed(ILogger logger, Exception exception, string operation);
}
