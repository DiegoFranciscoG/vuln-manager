using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Services;

public sealed class DashboardService(ProjectService projects, IAlertRepository alerts, ISyncRunRepository syncRuns)
{
    public async Task<DashboardDto> GetAsync(Actor actor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var summaries = await projects.ListAsync(actor, includeArchived: false, cancellationToken);
        var openAlerts = await alerts.ListAsync(actor.ProjectScope, onlyOpen: true, 1, 1, cancellationToken);
        var recent = await syncRuns.ListRecentAsync(50, cancellationToken);
        var latestPerSource = recent
            .GroupBy(r => r.Source)
            .Select(g => g.OrderByDescending(r => r.StartedAt).First())
            .OrderBy(r => r.Source)
            .Select(r => r.ToDto())
            .ToList();

        return new DashboardDto(
            summaries,
            summaries.Sum(s => s.Stats.Open),
            summaries.Sum(s => s.Stats.P1),
            summaries.Sum(s => s.Stats.Overdue),
            summaries.Sum(s => s.Stats.InKev),
            summaries.Sum(s => s.Stats.ForensicTriage),
            openAlerts.Total,
            latestPerSource);
    }

    public async Task<IReadOnlyList<SyncRunDto>> RecentSyncRunsAsync(int take, CancellationToken cancellationToken = default) =>
        (await syncRuns.ListRecentAsync(Math.Clamp(take, 1, 200), cancellationToken)).Select(r => r.ToDto()).ToList();

    public static IReadOnlyList<SyncSource> AllSources { get; } = Enum.GetValues<SyncSource>();
}
