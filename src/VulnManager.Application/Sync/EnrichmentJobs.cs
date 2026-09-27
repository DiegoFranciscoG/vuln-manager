using System.Globalization;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.External;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Options;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Sync;

/// <summary>CISA KEV catalog: conditional GET (ETag) and upsert by CVE id; flags vulnerabilities as in_kev.</summary>
public sealed class KevSyncJob(
    IKevRepository kevEntries,
    IVulnerabilityRepository vulnerabilities,
    IFindingRepository findings,
    ISyncRunRepository syncRuns,
    IKevClient client,
    IUnitOfWork unitOfWork,
    TimeProvider time) : ISyncJob
{
    public SyncSource Source => SyncSource.Kev;

    public string HttpClientName => HttpClientNames.Kev;

    public async Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        // Watermark: "etag|last-modified (RFC 1123)|catalogVersion".
        var previous = await syncRuns.LatestSuccessfulAsync(SyncSource.Kev, cancellationToken);
        var parts = previous?.Watermark?.Split('|') ?? [];
        var etag = parts.Length > 0 && parts[0].Length > 0 ? parts[0] : null;
        DateTimeOffset? lastModified = parts.Length > 1 && DateTimeOffset.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var lm) ? lm : null;
        var fetched = await client.FetchAsync(etag, lastModified, cancellationToken);
        if (fetched.NotModified)
        {
            return new SyncJobResult(SyncRunStatus.Skipped, 0, 0, previous?.Watermark, []);
        }

        var now = time.GetUtcNow();
        var stored = await kevEntries.GetAllAsync(cancellationToken);
        var updated = 0;
        foreach (var entry in fetched.Entries)
        {
            if (!stored.TryGetValue(entry.CveId, out var kev))
            {
                kev = new KevEntry(entry.CveId);
                kevEntries.Add(kev);
                stored[entry.CveId] = kev;
            }

            if (kev.Apply(entry.VendorProject, entry.Product, entry.VulnerabilityName, entry.DateAdded, entry.DueDate, entry.ShortDescription,
                    entry.RequiredAction, entry.KnownRansomware, entry.ForensicTriage, entry.Cwes, fetched.CatalogVersion ?? string.Empty))
            {
                updated++;
            }
        }

        var inFeed = fetched.Entries.Select(e => e.CveId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var removed in stored.Values.Where(k => k.RemovedAt is null && !inFeed.Contains(k.CveId)))
        {
            removed.MarkRemoved(now);
            updated++;
        }

        var changedVulnerabilities = new List<Guid>();
        foreach (var vulnerability in await vulnerabilities.ListMatchedWithCveAsync(cancellationToken))
        {
            if (vulnerability.SetKev(inFeed.Contains(vulnerability.CveId!)))
            {
                changedVulnerabilities.Add(vulnerability.Id);
                updated++;
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        var affected = await findings.GetProjectsWithVulnerabilitiesAsync(changedVulnerabilities, cancellationToken);
        var watermark = $"{fetched.ETag}|{fetched.LastModified?.ToString("R", CultureInfo.InvariantCulture)}|{fetched.CatalogVersion}";
        return new SyncJobResult(SyncRunStatus.Succeeded, fetched.Entries.Count, updated, watermark, affected);
    }
}

/// <summary>FIRST EPSS: batches of up to 100 CVE ids (the API limits the cve parameter to 2 000 characters).</summary>
public sealed class EpssSyncJob(
    IVulnerabilityRepository vulnerabilities,
    IFindingRepository findings,
    IEpssClient client,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<SyncOptions> options) : ISyncJob
{
    public const int BatchSize = 100;

    public SyncSource Source => SyncSource.Epss;

    public string HttpClientName => HttpClientNames.Epss;

    public async Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var threshold = now.AddHours(-options.Value.EpssIntervalHours);
        var due = (await vulnerabilities.ListMatchedWithCveAsync(cancellationToken))
            .Where(v => request.Trigger == SyncTrigger.Manual || v.EpssSyncedAt is null || v.EpssSyncedAt < threshold)
            .Take(options.Value.EnrichmentMaxPerRun)
            .ToList();
        if (due.Count == 0)
        {
            return SyncJobResult.Nothing();
        }

        var updated = 0;
        var changed = new List<Guid>();
        DateOnly? scoreDate = null;
        foreach (var chunk in due.Chunk(BatchSize))
        {
            var scores = (await client.GetScoresAsync(chunk.Select(v => v.CveId!).Distinct().ToList(), cancellationToken))
                .GroupBy(s => s.CveId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            foreach (var vulnerability in chunk)
            {
                if (scores.TryGetValue(vulnerability.CveId!, out var score))
                {
                    scoreDate = score.Date;
                    if (vulnerability.ApplyEpss(score.Epss, score.Percentile, score.Date, now))
                    {
                        updated++;
                        changed.Add(vulnerability.Id);
                    }
                }
                else
                {
                    vulnerability.MarkEpssSynced(now);
                }
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        var affected = await findings.GetProjectsWithVulnerabilitiesAsync(changed, cancellationToken);
        return new SyncJobResult(SyncRunStatus.Succeeded, due.Count, updated, scoreDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), affected);
    }
}

/// <summary>CVE Services: CISA ADP (Vulnrichment) SSVC decision points, and the CNA CVSS score when no other source has one.</summary>
public sealed class CveEnrichmentJob(
    IVulnerabilityRepository vulnerabilities,
    IFindingRepository findings,
    ICveServicesClient client,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<SyncOptions> options) : ISyncJob
{
    public SyncSource Source => SyncSource.Cve;

    public string HttpClientName => HttpClientNames.Cve;

    public async Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var threshold = now.AddDays(-options.Value.CveRecheckDays);
        var due = (await vulnerabilities.ListMatchedWithCveAsync(cancellationToken))
            .Where(v => v.CveSyncedAt is null || v.CveSyncedAt < threshold)
            .Take(options.Value.EnrichmentMaxPerRun)
            .ToList();
        if (due.Count == 0)
        {
            return SyncJobResult.Nothing();
        }

        var updated = 0;
        var changed = new List<Guid>();
        foreach (var vulnerability in due)
        {
            var data = await client.GetAsync(vulnerability.CveId!, cancellationToken);
            var didChange = false;
            if (data is null)
            {
                vulnerability.MarkCveSynced(now);
            }
            else
            {
                didChange |= vulnerability.ApplySsvc(data.Exploitation, data.Automatable, data.TechnicalImpact, now);
                if (data.CnaCvss is { } cvss)
                {
                    didChange |= vulnerability.ApplyPublishedCvss(cvss.Version, cvss.Vector, cvss.Score, CvssSource.Cna);
                }
            }

            if (didChange)
            {
                updated++;
                changed.Add(vulnerability.Id);
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        var affected = await findings.GetProjectsWithVulnerabilitiesAsync(changed, cancellationToken);
        return new SyncJobResult(SyncRunStatus.Succeeded, due.Count, updated, null, affected);
    }
}

/// <summary>NVD: only fills CVSS for CVEs that still have no score. The NVD client enforces the published rate limit.</summary>
public sealed class NvdEnrichmentJob(
    IVulnerabilityRepository vulnerabilities,
    IFindingRepository findings,
    INvdClient client,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<SyncOptions> options) : ISyncJob
{
    public SyncSource Source => SyncSource.Nvd;

    public string HttpClientName => HttpClientNames.Nvd;

    public async Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var threshold = now.AddDays(-options.Value.NvdRecheckDays);
        var due = (await vulnerabilities.ListMatchedWithCveAsync(cancellationToken))
            .Where(v => v.CvssScore is null && (v.NvdSyncedAt is null || v.NvdSyncedAt < threshold))
            .Take(options.Value.EnrichmentMaxPerRun)
            .ToList();
        if (due.Count == 0)
        {
            return SyncJobResult.Nothing();
        }

        var updated = 0;
        var changed = new List<Guid>();
        foreach (var vulnerability in due)
        {
            var cvss = await client.GetCvssAsync(vulnerability.CveId!, cancellationToken);
            vulnerability.MarkNvdSynced(now);
            if (cvss is not null && vulnerability.ApplyPublishedCvss(cvss.Version, cvss.Vector, cvss.Score, CvssSource.Nvd))
            {
                updated++;
                changed.Add(vulnerability.Id);
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        var affected = await findings.GetProjectsWithVulnerabilitiesAsync(changed, cancellationToken);
        return new SyncJobResult(SyncRunStatus.Succeeded, due.Count, updated, null, affected);
    }
}
