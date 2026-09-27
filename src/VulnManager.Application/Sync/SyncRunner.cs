using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.External;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Dtos;
using VulnManager.Application.Mappers;
using VulnManager.Application.Options;
using VulnManager.Application.Services;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Sync;

/// <summary>
/// Runs sync jobs, each in its own DI scope, records a <see cref="SyncRun"/> per source (requests, throttled responses,
/// updated items, watermark) and reconciles the affected projects at the end.
/// </summary>
public sealed partial class SyncRunner(
    IServiceScopeFactory scopes,
    IHttpCallStats stats,
    TimeProvider time,
    IOptions<SyncOptions> options,
    ILogger<SyncRunner> logger)
{
    /// <summary>KEV first (cheap, drives priority), then OSV matching, SSVC, missing CVSS and EPSS.</summary>
    public static IReadOnlyList<SyncSource> FullOrder { get; } = [SyncSource.Kev, SyncSource.Osv, SyncSource.Cve, SyncSource.Nvd, SyncSource.Epss];

    public async Task<IReadOnlyList<SyncRunDto>> RunAsync(SyncRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var sources = request.Source is { } single ? [single] : FullOrder;
        var affected = new HashSet<Guid>();
        var runs = new List<SyncRunDto>();

        foreach (var source in sources)
        {
            var (run, projects) = await RunSourceAsync(source, request, cancellationToken);
            if (run is not null)
            {
                runs.Add(run);
                affected.UnionWith(projects);
            }
        }

        await using var scope = scopes.CreateAsyncScope();
        var reconciliation = scope.ServiceProvider.GetRequiredService<FindingReconciliationService>();
        if (affected.Count > 0)
        {
            await reconciliation.ReconcileProjectsAsync(affected, cancellationToken);
        }

        var alerts = scope.ServiceProvider.GetRequiredService<AlertService>();
        await alerts.GenerateSlaAlertsAsync(cancellationToken);
        await alerts.DeliverPendingAsync(cancellationToken);
        return runs;
    }

    /// <summary>Marks runs left in RUNNING by a crashed instance as FAILED so the source is not blocked forever.</summary>
    public async Task<int> RecoverStaleRunsAsync(CancellationToken cancellationToken = default)
    {
        await using var scope = scopes.CreateAsyncScope();
        var repository = scope.ServiceProvider.GetRequiredService<ISyncRunRepository>();
        var now = time.GetUtcNow();
        return await repository.FailStaleRunsAsync(now.AddMinutes(-options.Value.StaleRunMinutes), now, cancellationToken);
    }

    private async Task<(SyncRunDto? Run, IReadOnlyCollection<Guid> Projects)> RunSourceAsync(SyncSource source, SyncRequest request, CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var job = scope.ServiceProvider.GetServices<ISyncJob>().Single(j => j.Source == source);
        var repository = scope.ServiceProvider.GetRequiredService<ISyncRunRepository>();
        var run = new SyncRun(source, request.Trigger, time.GetUtcNow());
        if (!await repository.TryStartAsync(run, cancellationToken))
        {
            LogAlreadyRunning(logger, source);
            return (null, []);
        }

        var before = stats.Snapshot(job.HttpClientName);
        SyncJobResult? result = null;
        string? error = null;
        var status = SyncRunStatus.Failed;
        try
        {
            result = await job.RunAsync(request, cancellationToken);
            status = result.Status;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            error = "Cancelado por apagado del servicio.";
        }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException or InvalidOperationException or FormatException or System.Text.Json.JsonException or OperationCanceledException)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            LogJobFailed(logger, ex, source);
        }

        var after = stats.Snapshot(job.HttpClientName);
        run.Finish(status, result?.ItemsRequested ?? 0, result?.ItemsUpdated ?? 0, after.Requests - before.Requests, after.Throttled - before.Throttled,
            result?.Watermark, error, time.GetUtcNow());
        await repository.CompleteAsync(run, CancellationToken.None);
        LogFinished(logger, source, run.Status, run.ItemsRequested, run.ItemsUpdated, run.HttpRequests, run.HttpThrottled);
        return (run.ToDto(), result?.AffectedProjects ?? []);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Sync {Source} skipped: another run is in progress")]
    private static partial void LogAlreadyRunning(ILogger logger, SyncSource source);

    [LoggerMessage(Level = LogLevel.Error, Message = "Sync {Source} failed")]
    private static partial void LogJobFailed(ILogger logger, Exception exception, SyncSource source);

    [LoggerMessage(Level = LogLevel.Information, Message = "Sync {Source} finished {Status}: requested={Requested} updated={Updated} http={Http} throttled={Throttled}")]
    private static partial void LogFinished(ILogger logger, SyncSource source, SyncRunStatus status, int requested, int updated, int http, int throttled);
}
