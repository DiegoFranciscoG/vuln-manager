using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;

namespace VulnManager.Infrastructure.Persistence.Repositories;

public sealed class FindingRepository(VulnManagerDbContext db) : IFindingRepository
{
    public async Task<IReadOnlyList<Finding>> ListByProjectAsync(Guid projectId, CancellationToken cancellationToken = default) =>
        await db.Findings.Where(f => f.ProjectId == projectId).ToListAsync(cancellationToken);

    public Task<Finding?> GetAsync(Guid id, bool includeHistory, CancellationToken cancellationToken = default)
    {
        var query = db.Findings.AsQueryable();
        if (includeHistory)
        {
            query = query.Include(f => f.History);
        }

        return query.FirstOrDefaultAsync(f => f.Id == id, cancellationToken);
    }

    public async Task<PagedResult<FindingListItemDto>> QueryAsync(FindingQuery query, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var rows = Filter(query, now);
        var total = await rows.CountAsync(cancellationToken);
        var page = await Sort(rows, query.Sort)
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToListAsync(cancellationToken);
        return new PagedResult<FindingListItemDto>(page.Select(r => r.ToDto(now)).ToList(), query.Page, query.PageSize, total);
    }

    public async Task<IReadOnlyList<FindingListItemDto>> ExportAsync(FindingQuery query, DateTimeOffset now, int maxRows, CancellationToken cancellationToken = default) =>
        (await Sort(Filter(query, now), query.Sort).Take(maxRows).ToListAsync(cancellationToken)).Select(r => r.ToDto(now)).ToList();

    public async Task<FindingDetailDto?> GetDetailAsync(Guid id, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var row = await Rows().FirstOrDefaultAsync(r => r.Finding.Id == id, cancellationToken);
        if (row is null)
        {
            return null;
        }

        var history = await db.FindingStatusHistory.AsNoTracking()
            .Where(h => h.FindingId == id)
            .OrderBy(h => h.ChangedAt).ThenBy(h => h.Id)
            .Select(h => new FindingHistoryDto(h.FromStatus, h.ToStatus, h.Justification, h.ChangeSource, h.ChangedBy, h.ChangedAt))
            .ToListAsync(cancellationToken);

        var v = row.Vulnerability;
        var f = row.Finding;
        return new FindingDetailDto(
            row.ToDto(now),
            v.Aliases,
            v.Details,
            v.CvssVersion,
            v.CvssVector,
            v.CvssSource?.ToString().ToUpperInvariant(),
            v.SsvcExploitation,
            v.SsvcAutomatable,
            v.SsvcTechnicalImpact,
            v.EpssDate,
            row.Kev?.DateAdded,
            row.Kev?.DueDate,
            row.Kev?.RequiredAction,
            row.Match?.FixedVersions ?? [],
            f.StatusReason,
            f.RiskAcceptedUntil,
            f.VexStatementId,
            AppJson.Deserialize<PriorityExplanationDto>(f.PriorityExplanation),
            AppJson.Deserialize<SlaExplanationDto>(f.SlaExplanation),
            history);
    }

    public async Task<IReadOnlyList<Finding>> ListOpenDueBeforeAsync(DateTimeOffset dueBefore, CancellationToken cancellationToken = default) =>
        await db.Findings.AsNoTracking()
            .Where(f => f.Status == FindingStatus.New && f.SlaDueAt != null && f.SlaDueAt < dueBefore)
            .ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Guid>> GetProjectsWithVulnerabilitiesAsync(IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken cancellationToken = default)
    {
        if (vulnerabilityIds.Count == 0)
        {
            return [];
        }

        var ids = vulnerabilityIds.ToList();
        var fromFindings = db.Findings.Where(f => ids.Contains(f.VulnerabilityId)).Select(f => f.ProjectId);
        var fromMatches = from p in db.Projects
                          where p.ArchivedAt == null && p.CurrentSbomImportId != null
                          where db.SbomComponents.Any(c => c.SbomImportId == p.CurrentSbomImportId
                                                           && db.ComponentVulnerabilities.Any(m => m.ComponentId == c.ComponentId && ids.Contains(m.VulnerabilityId)))
                          select p.Id;
        return await fromFindings.Union(fromMatches).Distinct().ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<ProjectFindingStatsDto>> GetStatsAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        var rows = await (from f in db.Findings
                          join v in db.Vulnerabilities on f.VulnerabilityId equals v.Id
                          group new { f.Status, f.PriorityLevel, f.SlaDueAt, f.ForensicTriageRequired, v.InKev } by f.ProjectId into g
                          select new
                          {
                              ProjectId = g.Key,
                              Open = g.Count(x => x.Status == FindingStatus.New),
                              P1 = g.Count(x => x.Status == FindingStatus.New && x.PriorityLevel == PriorityLevel.P1),
                              P2 = g.Count(x => x.Status == FindingStatus.New && x.PriorityLevel == PriorityLevel.P2),
                              P3 = g.Count(x => x.Status == FindingStatus.New && x.PriorityLevel == PriorityLevel.P3),
                              P4 = g.Count(x => x.Status == FindingStatus.New && x.PriorityLevel == PriorityLevel.P4),
                              Overdue = g.Count(x => x.Status == FindingStatus.New && x.SlaDueAt != null && x.SlaDueAt < now),
                              InKev = g.Count(x => x.Status == FindingStatus.New && x.InKev),
                              Forensic = g.Count(x => x.Status == FindingStatus.New && x.ForensicTriageRequired),
                              Closed = g.Count(x => x.Status != FindingStatus.New),
                          }).ToListAsync(cancellationToken);

        return rows.Select(r => new ProjectFindingStatsDto(r.ProjectId, r.Open, r.P1, r.P2, r.P3, r.P4, r.Overdue, r.InKev, r.Forensic, r.Closed)).ToList();
    }

    public void Add(Finding finding) => db.Findings.Add(finding);

    private IQueryable<FindingRow> Rows() =>
        from f in db.Findings.AsNoTracking()
        join p in db.Projects on f.ProjectId equals p.Id
        join c in db.Components on f.ComponentId equals c.Id
        join v in db.Vulnerabilities on f.VulnerabilityId equals v.Id
        join m in db.ComponentVulnerabilities on new { f.ComponentId, f.VulnerabilityId } equals new { m.ComponentId, m.VulnerabilityId } into matches
        from m in matches.DefaultIfEmpty()
        join k in db.KevEntries on v.CveId equals k.CveId into kevs
        from k in kevs.DefaultIfEmpty()
        select new FindingRow { Finding = f, ProjectName = p.Name, Component = c, Vulnerability = v, Match = m, Kev = k };

    private IQueryable<FindingRow> Filter(FindingQuery query, DateTimeOffset now)
    {
        var rows = Rows();
        if (query.ProjectId is { } projectId)
        {
            rows = rows.Where(r => r.Finding.ProjectId == projectId);
        }

        if (query.Statuses is { Count: > 0 } statuses)
        {
            var list = statuses.ToList();
            rows = rows.Where(r => list.Contains(r.Finding.Status));
        }

        if (query.Priorities is { Count: > 0 } priorities)
        {
            var list = priorities.ToList();
            rows = rows.Where(r => list.Contains(r.Finding.PriorityLevel));
        }

        if (query.Severities is { Count: > 0 } severities)
        {
            var list = severities.ToList();
            rows = rows.Where(r => list.Contains(r.Vulnerability.Severity));
        }

        if (query.InKev is { } inKev)
        {
            rows = rows.Where(r => r.Vulnerability.InKev == inKev);
        }

        if (query.FixAvailable is { } fix)
        {
            rows = rows.Where(r => (r.Match != null && r.Match.FixAvailable) == fix);
        }

        if (query.Overdue is { } overdue)
        {
            rows = overdue
                ? rows.Where(r => r.Finding.Status == FindingStatus.New && r.Finding.SlaDueAt != null && r.Finding.SlaDueAt < now)
                : rows.Where(r => !(r.Finding.Status == FindingStatus.New && r.Finding.SlaDueAt != null && r.Finding.SlaDueAt < now));
        }

        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var pattern = "%" + LikePattern.Escape(query.Search.Trim()) + "%";
            rows = rows.Where(r => EF.Functions.ILike(r.Component.Purl, pattern, LikePattern.EscapeCharacter)
                                   || EF.Functions.ILike(r.Vulnerability.ExternalId, pattern, LikePattern.EscapeCharacter)
                                   || (r.Vulnerability.CveId != null && EF.Functions.ILike(r.Vulnerability.CveId, pattern, LikePattern.EscapeCharacter))
                                   || (r.Vulnerability.Summary != null && EF.Functions.ILike(r.Vulnerability.Summary, pattern, LikePattern.EscapeCharacter)));
        }

        return rows;
    }

    private static IQueryable<FindingRow> Sort(IQueryable<FindingRow> rows, FindingSort sort) => sort switch
    {
        FindingSort.SlaDue => rows.OrderBy(r => r.Finding.SlaDueAt == null).ThenBy(r => r.Finding.SlaDueAt).ThenBy(r => r.Finding.PriorityLevel),
        FindingSort.Cvss => rows.OrderBy(r => r.Vulnerability.CvssScore == null).ThenByDescending(r => r.Vulnerability.CvssScore).ThenBy(r => r.Finding.PriorityLevel),
        FindingSort.Epss => rows.OrderBy(r => r.Vulnerability.EpssPercentile == null).ThenByDescending(r => r.Vulnerability.EpssPercentile).ThenBy(r => r.Finding.PriorityLevel),
        FindingSort.Detected => rows.OrderByDescending(r => r.Finding.FirstDetectedAt),
        // Level first, then the documented tie-breakers: KEV, ransomware, EPSS, CVSS, fix available, SLA, age.
        _ => rows.OrderBy(r => r.Finding.Status != FindingStatus.New)
            .ThenBy(r => r.Finding.PriorityLevel)
            .ThenByDescending(r => r.Vulnerability.InKev)
            .ThenByDescending(r => r.Kev != null && r.Kev.KnownRansomwareCampaignUse)
            .ThenBy(r => r.Vulnerability.EpssPercentile == null)
            .ThenByDescending(r => r.Vulnerability.EpssPercentile)
            .ThenBy(r => r.Vulnerability.CvssScore == null)
            .ThenByDescending(r => r.Vulnerability.CvssScore)
            .ThenByDescending(r => r.Match != null && r.Match.FixAvailable)
            .ThenBy(r => r.Finding.SlaDueAt == null)
            .ThenBy(r => r.Finding.SlaDueAt)
            .ThenBy(r => r.Finding.FirstDetectedAt),
    };

    /// <summary>Row of the joined query. An object initializer (not a constructor) lets EF Core compose filters and sorting on it.</summary>
    private sealed class FindingRow
    {
        public required Finding Finding { get; init; }

        public required string ProjectName { get; init; }

        public required Component Component { get; init; }

        public required Vulnerability Vulnerability { get; init; }

        public ComponentVulnerability? Match { get; init; }

        public KevEntry? Kev { get; init; }

        public FindingListItemDto ToDto(DateTimeOffset now)
        {
            var open = Finding.Status == FindingStatus.New;
            int? daysRemaining = Finding.SlaDueAt is { } due && open ? (int)Math.Floor((due - now).TotalDays) : null;
            return new FindingListItemDto(
                Finding.Id,
                Finding.ProjectId,
                ProjectName,
                Component.Purl,
                Component.Name,
                Component.Version,
                Vulnerability.ExternalId,
                Vulnerability.CveId,
                Vulnerability.Summary,
                Vulnerability.Severity,
                Vulnerability.CvssScore,
                Vulnerability.EpssScore,
                Vulnerability.EpssPercentile,
                Vulnerability.InKev,
                Kev?.KnownRansomwareCampaignUse ?? false,
                Finding.Status,
                Finding.PriorityLevel,
                Match?.FixAvailable ?? false,
                Match?.SuggestedFixVersion,
                Finding.SlaDueAt,
                daysRemaining,
                open && Finding.SlaDueAt is { } d && d < now,
                Finding.ForensicTriageRequired,
                Finding.FirstDetectedAt);
        }
    }
}
