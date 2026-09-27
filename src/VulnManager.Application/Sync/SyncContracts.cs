using VulnManager.Application.Abstractions;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Sync;

public sealed record SyncJobResult(
    SyncRunStatus Status,
    int ItemsRequested,
    int ItemsUpdated,
    string? Watermark,
    IReadOnlyCollection<Guid> AffectedProjects)
{
    public static SyncJobResult Nothing(string? watermark = null) => new(SyncRunStatus.Succeeded, 0, 0, watermark, []);
}

/// <summary>One external source. Jobs must be idempotent: a second run without new upstream data updates nothing.</summary>
public interface ISyncJob
{
    SyncSource Source { get; }

    /// <summary>Name of the HttpClient used, to attribute request and throttling counters to the run.</summary>
    string HttpClientName { get; }

    Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken);
}

public static class HttpClientNames
{
    public const string Osv = "osv";
    public const string Kev = "kev";
    public const string Epss = "epss";
    public const string Cve = "cve";
    public const string Nvd = "nvd";
    public const string Webhook = "webhook";
}
