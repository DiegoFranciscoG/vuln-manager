using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Options;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Services;

public static class AuditActions
{
    public const string ProjectCreated = "PROJECT_CREATED";
    public const string ProjectUpdated = "PROJECT_UPDATED";
    public const string ProjectArchived = "PROJECT_ARCHIVED";
    public const string ApiKeyCreated = "API_KEY_CREATED";
    public const string ApiKeyRevoked = "API_KEY_REVOKED";
    public const string SbomImported = "SBOM_IMPORTED";
    public const string FindingStatusChanged = "FINDING_STATUS_CHANGED";
    public const string VexCreated = "VEX_CREATED";
    public const string VexRevoked = "VEX_REVOKED";
    public const string RuleCreated = "RULE_CREATED";
    public const string RuleActivated = "RULE_ACTIVATED";
    public const string SyncTriggered = "SYNC_TRIGGERED";
    public const string AuditPurged = "AUDIT_PURGED";
}

/// <summary>Records who did what. Entries are saved together with the business change (same unit of work).</summary>
public sealed class AuditService(IAuditLogRepository auditLog, IUnitOfWork unitOfWork, TimeProvider time, IOptions<AuditOptions> options)
{
    public void Record(Actor actor, string action, string entityType, object entityId, object? details = null)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(entityId);
        auditLog.Add(new AuditLogEntry(
            actor.Type,
            actor.Id,
            action,
            entityType,
            entityId.ToString() ?? string.Empty,
            details is null ? null : AppJson.Serialize(details),
            time.GetUtcNow()));
    }

    public Task<PagedResult<AuditEntryDto>> ListAsync(Actor actor, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede consultar la auditoría.");
        }

        return auditLog.ListAsync(Math.Max(1, page), Math.Clamp(pageSize, 1, 200), cancellationToken);
    }

    /// <summary>Retention purge (LOPDP art. 10 i). The purge itself is audited.</summary>
    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken = default)
    {
        var cutoff = time.GetUtcNow().AddDays(-options.Value.RetentionDays);
        var purged = await auditLog.PurgeOlderThanAsync(cutoff, cancellationToken);
        if (purged > 0)
        {
            Record(Actor.System, AuditActions.AuditPurged, "audit_log", "retention", new { purged, cutoff });
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }

        return purged;
    }
}
