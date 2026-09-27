using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Domain.Entities;

namespace VulnManager.Infrastructure.Persistence.Repositories;

public sealed class VexRepository(VulnManagerDbContext db) : IVexRepository
{
    public async Task<IReadOnlyList<VexStatement>> ListByProjectAsync(Guid projectId, bool includeRevoked, CancellationToken cancellationToken = default) =>
        await db.VexStatements
            .Where(v => v.ProjectId == projectId && (includeRevoked || v.RevokedAt == null))
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync(cancellationToken);

    public Task<VexStatement?> GetAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.VexStatements.FirstOrDefaultAsync(v => v.Id == id, cancellationToken);

    public void Add(VexStatement statement) => db.VexStatements.Add(statement);
}

public sealed class PriorityRuleRepository(VulnManagerDbContext db) : IPriorityRuleRepository
{
    public Task<PriorityRuleVersion?> GetActiveAsync(CancellationToken cancellationToken = default) =>
        db.PriorityRules.FirstOrDefaultAsync(r => r.IsActive, cancellationToken);

    public Task<PriorityRuleVersion?> GetAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.PriorityRules.FirstOrDefaultAsync(r => r.Id == id, cancellationToken);

    public async Task<IReadOnlyList<PriorityRuleVersion>> ListAsync(CancellationToken cancellationToken = default) =>
        await db.PriorityRules.AsNoTracking().OrderByDescending(r => r.Version).ToListAsync(cancellationToken);

    public async Task<int> MaxVersionAsync(CancellationToken cancellationToken = default) =>
        await db.PriorityRules.MaxAsync(r => (int?)r.Version, cancellationToken) ?? 0;

    public void Add(PriorityRuleVersion rule) => db.PriorityRules.Add(rule);
}

public sealed class AlertRepository(VulnManagerDbContext db) : IAlertRepository
{
    public async Task<HashSet<string>> ExistingKeysAsync(IReadOnlyCollection<string> dedupKeys, CancellationToken cancellationToken = default)
    {
        if (dedupKeys.Count == 0)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        var list = dedupKeys.ToList();
        var existing = await db.Alerts.Where(a => list.Contains(a.DedupKey)).Select(a => a.DedupKey).ToListAsync(cancellationToken);
        return existing.ToHashSet(StringComparer.Ordinal);
    }

    public Task<Alert?> GetAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.Alerts.FirstOrDefaultAsync(a => a.Id == id, cancellationToken);

    public async Task<PagedResult<AlertDto>> ListAsync(Guid? projectId, bool onlyOpen, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var query = from a in db.Alerts.AsNoTracking()
                    join p in db.Projects on a.ProjectId equals p.Id
                    where (projectId == null || a.ProjectId == projectId) && (!onlyOpen || a.AcknowledgedAt == null)
                    select new AlertDto(a.Id, a.ProjectId, p.Name, a.FindingId, a.Type, a.Message, a.CreatedAt, a.AcknowledgedAt);
        var total = await query.CountAsync(cancellationToken);
        var items = await query.OrderByDescending(a => a.CreatedAt).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        return new PagedResult<AlertDto>(items, page, pageSize, total);
    }

    public async Task<IReadOnlyList<Alert>> ListUndeliveredAsync(int take, CancellationToken cancellationToken = default) =>
        await db.Alerts.Where(a => a.WebhookDeliveredAt == null && a.AcknowledgedAt == null)
            .OrderBy(a => a.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);

    public void Add(Alert alert) => db.Alerts.Add(alert);
}

public sealed class SyncRunRepository(VulnManagerDbContext db) : ISyncRunRepository
{
    private static readonly SyncRunStatus[] SuccessStatuses = [SyncRunStatus.Succeeded, SyncRunStatus.Skipped, SyncRunStatus.Partial];

    public Task<SyncRun?> LatestSuccessfulAsync(SyncSource source, CancellationToken cancellationToken = default) =>
        db.SyncRuns.AsNoTracking()
            .Where(r => r.Source == source && SuccessStatuses.Contains(r.Status))
            .OrderByDescending(r => r.StartedAt)
            .FirstOrDefaultAsync(cancellationToken);

    public async Task<IReadOnlyList<SyncRun>> ListRecentAsync(int take, CancellationToken cancellationToken = default) =>
        await db.SyncRuns.AsNoTracking().OrderByDescending(r => r.StartedAt).Take(take).ToListAsync(cancellationToken);

    public Task<int> FailStaleRunsAsync(DateTimeOffset startedBefore, DateTimeOffset now, CancellationToken cancellationToken = default) =>
        db.SyncRuns
            .Where(r => r.Status == SyncRunStatus.Running && r.StartedAt < startedBefore)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, SyncRunStatus.Failed)
                .SetProperty(r => r.FinishedAt, now)
                .SetProperty(r => r.ErrorMessage, "Interrumpido: la instancia se detuvo durante la ejecución."), cancellationToken);

    public async Task<bool> TryStartAsync(SyncRun run, CancellationToken cancellationToken = default)
    {
        db.SyncRuns.Add(run);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            db.Entry(run).State = EntityState.Detached;
            return true;
        }
        catch (DbUpdateException ex) when (UnitOfWork.IsUniqueViolation(ex))
        {
            db.Entry(run).State = EntityState.Detached;
            return false;
        }
    }

    /// <summary>Updates the row directly so that unsaved changes of a failed job are never flushed by accident.</summary>
    public Task CompleteAsync(SyncRun run, CancellationToken cancellationToken = default) =>
        db.SyncRuns.Where(r => r.Id == run.Id).ExecuteUpdateAsync(s => s
            .SetProperty(r => r.Status, run.Status)
            .SetProperty(r => r.FinishedAt, run.FinishedAt)
            .SetProperty(r => r.ItemsRequested, run.ItemsRequested)
            .SetProperty(r => r.ItemsUpdated, run.ItemsUpdated)
            .SetProperty(r => r.HttpRequests, run.HttpRequests)
            .SetProperty(r => r.HttpThrottled, run.HttpThrottled)
            .SetProperty(r => r.Watermark, run.Watermark)
            .SetProperty(r => r.ErrorMessage, run.ErrorMessage), cancellationToken);
}

public sealed class AuditLogRepository(VulnManagerDbContext db) : IAuditLogRepository
{
    public void Add(AuditLogEntry entry) => db.AuditLog.Add(entry);

    public async Task<PagedResult<AuditEntryDto>> ListAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var total = await db.AuditLog.CountAsync(cancellationToken);
        var items = await db.AuditLog.AsNoTracking()
            .OrderByDescending(a => a.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => new AuditEntryDto(a.Id, a.OccurredAt, a.ActorType, a.ActorId, a.Action, a.EntityType, a.EntityId, a.Details))
            .ToListAsync(cancellationToken);
        return new PagedResult<AuditEntryDto>(items, page, pageSize, total);
    }

    /// <summary>The append-only trigger allows DELETE only when this transaction-local flag is set.</summary>
    public Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        var strategy = db.Database.CreateExecutionStrategy();
        return strategy.ExecuteAsync(async () =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
            await db.Database.ExecuteSqlRawAsync("SET LOCAL vulnmanager.allow_retention_purge = 'on'", cancellationToken);
            var deleted = await db.AuditLog.Where(a => a.OccurredAt < cutoff).ExecuteDeleteAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return deleted;
        });
    }
}
