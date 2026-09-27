using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.External;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Options;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Packages;
using VulnManager.Domain.Scoring;

namespace VulnManager.Application.Sync;

/// <summary>Matches inventory components against OSV.dev (querybatch by purl, then vulnerability details).</summary>
public sealed class OsvSyncJob(
    IComponentRepository components,
    IVulnerabilityRepository vulnerabilities,
    IKevRepository kevEntries,
    ISbomImportRepository imports,
    IOsvClient osv,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<SyncOptions> options) : ISyncJob
{
    private const int DetailConcurrency = 4;

    public SyncSource Source => SyncSource.Osv;

    public string HttpClientName => HttpClientNames.Osv;

    public async Task<SyncJobResult> RunAsync(SyncRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var settings = options.Value;
        var now = time.GetUtcNow();
        var due = await components.ListDueForOsvAsync(request.ProjectId, now.AddHours(-settings.OsvRecheckHours), settings.OsvMaxComponentsPerRun, cancellationToken);
        if (due.Count == 0)
        {
            return SyncJobResult.Nothing();
        }

        var refsByComponent = new Dictionary<Guid, IReadOnlyList<OsvVulnerabilityRef>>();
        foreach (var chunk in due.Chunk(settings.OsvBatchSize))
        {
            var results = await osv.QueryBatchAsync(chunk.Select(c => c.Purl).ToList(), cancellationToken);
            for (var i = 0; i < chunk.Length; i++)
            {
                refsByComponent[chunk[i].Id] = results[i];
            }
        }

        var ids = refsByComponent.Values.SelectMany(r => r).Select(r => r.Id).Distinct(StringComparer.Ordinal).ToList();
        var details = await FetchDetailsAsync(ids, cancellationToken);
        var stored = await vulnerabilities.GetByExternalIdsAsync(details.Keys.ToList(), cancellationToken);
        var updated = 0;

        foreach (var detail in details.Values)
        {
            if (!stored.TryGetValue(detail.Id, out var vulnerability))
            {
                vulnerability = new Vulnerability(detail.Id, now);
                vulnerabilities.Add(vulnerability);
                stored[detail.Id] = vulnerability;
            }

            var vector = detail.Severity.FirstOrDefault(s => s.Type == "CVSS_V3")?.Score ?? detail.Severity.FirstOrDefault(s => s.Type == "CVSS_V4")?.Score;
            if (vulnerability.ApplyOsvRecord(detail.Modified, detail.Published, detail.Withdrawn, detail.Aliases, detail.Summary, detail.Details,
                    vector, SeverityScale.FromText(detail.DatabaseSeverity), now))
            {
                updated++;
            }
        }

        // Flag KEV membership immediately so a new advisory does not wait for the next KEV run.
        var cves = stored.Values.Where(v => v.CveId is not null).Select(v => v.CveId!).Distinct().ToList();
        var kev = await kevEntries.GetByCveIdsAsync(cves, cancellationToken);
        foreach (var vulnerability in stored.Values.Where(v => v.CveId is not null))
        {
            if (vulnerability.SetKev(kev.TryGetValue(vulnerability.CveId!, out var entry) && entry.RemovedAt is null))
            {
                updated++;
            }
        }

        var existingMatches = (await vulnerabilities.GetMatchesAsync(due.Select(c => c.Id).ToList(), cancellationToken))
            .ToDictionary(m => (m.ComponentId, m.VulnerabilityId));

        foreach (var component in due)
        {
            var purl = PackageUrl.Parse(component.Purl);
            var current = new HashSet<Guid>();
            foreach (var reference in refsByComponent[component.Id])
            {
                if (!details.TryGetValue(reference.Id, out var detail))
                {
                    continue;
                }

                var vulnerability = stored[detail.Id];
                current.Add(vulnerability.Id);
                var (fixedVersions, suggested) = FixedVersionResolver.Resolve(detail.Affected, purl);
                if (existingMatches.TryGetValue((component.Id, vulnerability.Id), out var match))
                {
                    if (match.Refresh(fixedVersions, suggested, now))
                    {
                        updated++;
                    }
                }
                else
                {
                    vulnerabilities.AddMatch(new ComponentVulnerability(component.Id, vulnerability.Id, fixedVersions, suggested, now));
                    updated++;
                }
            }

            foreach (var stale in existingMatches.Values.Where(m => m.ComponentId == component.Id && !current.Contains(m.VulnerabilityId)))
            {
                vulnerabilities.RemoveMatch(stale);
                updated++;
            }

            component.MarkChecked(now);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        var affected = updated > 0 ? await imports.GetProjectsUsingComponentsAsync(due.Select(c => c.Id).ToList(), cancellationToken) : [];
        return new SyncJobResult(SyncRunStatus.Succeeded, due.Count, updated, null, affected);
    }

    private async Task<Dictionary<string, OsvVulnerability>> FetchDetailsAsync(IReadOnlyList<string> ids, CancellationToken cancellationToken)
    {
        var results = new System.Collections.Concurrent.ConcurrentDictionary<string, OsvVulnerability>(StringComparer.Ordinal);
        await Parallel.ForEachAsync(ids, new ParallelOptions { MaxDegreeOfParallelism = DetailConcurrency, CancellationToken = cancellationToken }, async (id, ct) =>
        {
            var detail = await osv.GetVulnerabilityAsync(id, ct);
            if (detail is not null)
            {
                results[id] = detail;
            }
        });
        return new Dictionary<string, OsvVulnerability>(results, StringComparer.Ordinal);
    }
}
