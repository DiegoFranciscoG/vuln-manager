using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Options;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Services;

public sealed partial class AlertService(
    IAlertRepository alerts,
    IFindingRepository findings,
    IProjectRepository projects,
    IAlertNotifier notifier,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<FindingOptions> options,
    ILogger<AlertService> logger)
{
    public Task<PagedResult<AlertDto>> ListAsync(Actor actor, Guid? projectId, bool onlyOpen, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (actor.ProjectScope is { } scope)
        {
            projectId = scope;
        }

        return alerts.ListAsync(projectId, onlyOpen, Math.Max(1, page), Math.Clamp(pageSize, 1, 200), cancellationToken);
    }

    public async Task AcknowledgeAsync(Actor actor, Guid id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.CanTriage)
        {
            throw new ForbiddenException("Se requiere rol Analyst o Admin para atender alertas.");
        }

        var alert = await alerts.GetAsync(id, cancellationToken);
        if (alert is null || !actor.CanAccessProject(alert.ProjectId))
        {
            throw NotFoundException.For("Alerta", id);
        }

        alert.Acknowledge(actor.Id, time.GetUtcNow());
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    /// <summary>SLA_DUE_SOON once per finding, SLA_OVERDUE once per deadline. Idempotent thanks to the dedup keys.</summary>
    public async Task<int> GenerateSlaAlertsAsync(CancellationToken cancellationToken = default)
    {
        var now = time.GetUtcNow();
        var due = await findings.ListOpenDueBeforeAsync(now.AddHours(options.Value.SlaDueSoonHours), cancellationToken);
        if (due.Count == 0)
        {
            return 0;
        }

        var pending = due.Select(f =>
        {
            var overdue = f.SlaDueAt <= now;
            var dueText = f.SlaDueAt!.Value.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
            return overdue
                ? new Alert(f.ProjectId, f.Id, AlertType.SlaOverdue, $"SLA vencido el {dueText} (prioridad {f.PriorityLevel}).",
                    $"SLA_OVERDUE:{f.Id}:{f.SlaDueAt.Value.ToString("yyyyMMdd", CultureInfo.InvariantCulture)}", now)
                : new Alert(f.ProjectId, f.Id, AlertType.SlaDueSoon, $"SLA vence el {dueText} (prioridad {f.PriorityLevel}).",
                    $"SLA_DUE_SOON:{f.Id}:{f.SlaDueAt.Value.ToString("yyyyMMdd", CultureInfo.InvariantCulture)}", now);
        }).ToList();

        var existing = await alerts.ExistingKeysAsync(pending.Select(a => a.DedupKey).ToList(), cancellationToken);
        var created = 0;
        foreach (var alert in pending.Where(a => existing.Add(a.DedupKey)))
        {
            alerts.Add(alert);
            created++;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return created;
    }

    /// <summary>Sends undelivered alerts to the configured webhook, if any.</summary>
    public async Task<int> DeliverPendingAsync(CancellationToken cancellationToken = default)
    {
        if (!notifier.IsEnabled)
        {
            return 0;
        }

        var pending = await alerts.ListUndeliveredAsync(50, cancellationToken);
        var names = (await projects.ListAsync(includeArchived: true, cancellationToken)).ToDictionary(p => p.Id, p => p.Name);
        var delivered = 0;
        foreach (var alert in pending)
        {
            if (await notifier.NotifyAsync(alert, names.GetValueOrDefault(alert.ProjectId, "?"), cancellationToken))
            {
                alert.MarkDelivered(time.GetUtcNow());
                delivered++;
            }
            else
            {
                LogDeliveryFailed(logger, alert.Id);
                break;
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return delivered;
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Webhook delivery failed for alert {AlertId}; it will be retried")]
    private static partial void LogDeliveryFailed(ILogger logger, Guid alertId);
}
