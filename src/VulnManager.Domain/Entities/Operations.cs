namespace VulnManager.Domain.Entities;

public enum AlertType
{
    NewP1 = 0,
    NewKevMatch = 1,
    SlaDueSoon = 2,
    SlaOverdue = 3,
    ForensicTriage = 4,
}

/// <summary>In-app alert, optionally delivered to a webhook. <see cref="DedupKey"/> makes alert generation idempotent.</summary>
public sealed class Alert
{
    private Alert()
    {
    }

    public Alert(Guid projectId, Guid? findingId, AlertType type, string message, string dedupKey, DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        ProjectId = projectId;
        FindingId = findingId;
        Type = type;
        Message = message.Length > 500 ? message[..500] : message;
        DedupKey = dedupKey;
        CreatedAt = now;
    }

    public Guid Id { get; private set; }

    public Guid ProjectId { get; private set; }

    public Guid? FindingId { get; private set; }

    public AlertType Type { get; private set; }

    public string Message { get; private set; } = string.Empty;

    public string DedupKey { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? AcknowledgedAt { get; private set; }

    public string? AcknowledgedBy { get; private set; }

    public DateTimeOffset? WebhookDeliveredAt { get; private set; }

    public void Acknowledge(string actor, DateTimeOffset now)
    {
        if (AcknowledgedAt is not null)
        {
            return;
        }

        AcknowledgedAt = now;
        AcknowledgedBy = actor;
    }

    public void MarkDelivered(DateTimeOffset now) => WebhookDeliveredAt = now;
}

public enum SyncSource
{
    Osv = 0,
    Kev = 1,
    Epss = 2,
    Cve = 3,
    Nvd = 4,
}

public enum SyncTrigger
{
    Scheduled = 0,
    Manual = 1,
    SbomImport = 2,
    Startup = 3,
    External = 4,
}

public enum SyncRunStatus
{
    Running = 0,
    Succeeded = 1,
    Partial = 2,
    Failed = 3,
    Skipped = 4,
}

/// <summary>One execution of a synchronization job, with counters that prove idempotency and rate-limit compliance.</summary>
public sealed class SyncRun
{
    private SyncRun()
    {
    }

    public SyncRun(SyncSource source, SyncTrigger trigger, DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        Source = source;
        Trigger = trigger;
        Status = SyncRunStatus.Running;
        StartedAt = now;
    }

    public Guid Id { get; private set; }

    public SyncSource Source { get; private set; }

    public SyncTrigger Trigger { get; private set; }

    public SyncRunStatus Status { get; private set; }

    public DateTimeOffset StartedAt { get; private set; }

    public DateTimeOffset? FinishedAt { get; private set; }

    public int ItemsRequested { get; private set; }

    public int ItemsUpdated { get; private set; }

    public int HttpRequests { get; private set; }

    public int HttpThrottled { get; private set; }

    public string? Watermark { get; private set; }

    public string? ErrorMessage { get; private set; }

    public void Finish(SyncRunStatus status, int itemsRequested, int itemsUpdated, int httpRequests, int httpThrottled, string? watermark, string? error, DateTimeOffset now)
    {
        Status = status;
        ItemsRequested = itemsRequested;
        ItemsUpdated = itemsUpdated;
        HttpRequests = httpRequests;
        HttpThrottled = httpThrottled;
        Watermark = watermark is { Length: > 100 } ? watermark[..100] : watermark;
        ErrorMessage = error is { Length: > 1000 } ? error[..1000] : error;
        FinishedAt = now;
    }
}

public enum ActorType
{
    User = 0,
    ApiKey = 1,
    System = 2,
}

/// <summary>Append-only audit entry. Never stores secrets or personal data (LOPDP art. 10 e).</summary>
public sealed class AuditLogEntry
{
    private AuditLogEntry()
    {
    }

    public AuditLogEntry(ActorType actorType, string actorId, string action, string entityType, string entityId, string? detailsJson, DateTimeOffset now)
    {
        OccurredAt = now;
        ActorType = actorType;
        ActorId = actorId;
        Action = action;
        EntityType = entityType;
        EntityId = entityId;
        Details = detailsJson;
    }

    public long Id { get; private set; }

    public DateTimeOffset OccurredAt { get; private set; }

    public ActorType ActorType { get; private set; }

    public string ActorId { get; private set; } = string.Empty;

    public string Action { get; private set; } = string.Empty;

    public string EntityType { get; private set; } = string.Empty;

    public string EntityId { get; private set; } = string.Empty;

    public string? Details { get; private set; }
}
