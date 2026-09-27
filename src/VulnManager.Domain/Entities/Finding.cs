using VulnManager.Domain.Common;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Sla;

namespace VulnManager.Domain.Entities;

/// <summary>A vulnerability present in a component of a project. Status changes go through <see cref="FindingTransitions"/>.</summary>
public sealed class Finding
{
    public const string SystemActor = "system";

    private readonly List<FindingStatusChange> _history = [];

    private Finding()
    {
    }

    private Finding(Guid projectId, Guid componentId, Guid vulnerabilityId, Guid importId, DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        ProjectId = projectId;
        ComponentId = componentId;
        VulnerabilityId = vulnerabilityId;
        DetectedInImportId = importId;
        Status = FindingStatus.New;
        FirstDetectedAt = now;
        LastSeenAt = now;
        UpdatedAt = now;
        SlaStartedAt = now;
        _history.Add(new FindingStatusChange(Id, null, FindingStatus.New, null, null, StatusChangeSource.SbomImport, SystemActor, now));
    }

    public Guid Id { get; private set; }

    public Guid ProjectId { get; private set; }

    public Guid ComponentId { get; private set; }

    public Guid VulnerabilityId { get; private set; }

    public FindingStatus Status { get; private set; }

    public string? StatusReason { get; private set; }

    public DateOnly? RiskAcceptedUntil { get; private set; }

    public Guid? VexStatementId { get; private set; }

    public PriorityLevel PriorityLevel { get; private set; } = PriorityLevel.P4;

    public Guid? PriorityRuleId { get; private set; }

    public string PriorityExplanation { get; private set; } = "{}";

    public SlaPolicyType SlaPolicy { get; private set; }

    public int? SlaRow { get; private set; }

    public int? SlaDays { get; private set; }

    public DateTimeOffset SlaStartedAt { get; private set; }

    public DateTimeOffset? SlaDueAt { get; private set; }

    public string SlaExplanation { get; private set; } = "{}";

    public bool ForensicTriageRequired { get; private set; }

    public DateTimeOffset FirstDetectedAt { get; private set; }

    public DateTimeOffset LastSeenAt { get; private set; }

    public DateTimeOffset? ResolvedAt { get; private set; }

    public Guid DetectedInImportId { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public uint Version { get; private set; }

    public IReadOnlyList<FindingStatusChange> History => _history;

    public static Finding Detect(Guid projectId, Guid componentId, Guid vulnerabilityId, Guid importId, DateTimeOffset now) =>
        new(projectId, componentId, vulnerabilityId, importId, now);

    public void ChangeStatus(
        FindingStatus to,
        StatusChangeSource source,
        string actor,
        string? justification,
        DateOnly? riskAcceptedUntil,
        Guid? vexStatementId,
        DateTimeOffset now,
        int maxAcceptanceDays)
    {
        var errors = FindingTransitions.Check(new TransitionRequest(
            Status, to, source, justification, riskAcceptedUntil, DateOnly.FromDateTime(now.UtcDateTime), maxAcceptanceDays));
        if (errors.Count > 0)
        {
            throw new DomainException(string.Join(" ", errors));
        }

        if (to == FindingStatus.NotAffected && vexStatementId is null)
        {
            throw new DomainException("NOT_AFFECTED requiere una declaración VEX.");
        }

        var from = Status;
        Status = to;
        StatusReason = string.IsNullOrWhiteSpace(justification) ? null : justification.Trim();
        RiskAcceptedUntil = to == FindingStatus.Accepted ? riskAcceptedUntil : null;
        VexStatementId = to == FindingStatus.NotAffected ? vexStatementId : null;
        ResolvedAt = FindingTransitions.IsOpen(to) ? null : now;
        UpdatedAt = now;
        _history.Add(new FindingStatusChange(Id, from, to, StatusReason, vexStatementId, source, actor, now));
    }

    public void MarkSeen(DateTimeOffset now) => LastSeenAt = now;

    /// <summary>Returns true when the level or its explanation changed.</summary>
    public bool ApplyPriority(PriorityLevel level, Guid ruleId, string explanationJson, DateTimeOffset now)
    {
        if (PriorityLevel == level && PriorityRuleId == ruleId && PriorityExplanation == explanationJson)
        {
            return false;
        }

        PriorityLevel = level;
        PriorityRuleId = ruleId;
        PriorityExplanation = explanationJson;
        UpdatedAt = now;
        return true;
    }

    /// <summary>Returns true when the deadline changed (BOD 26-04 timelines are dynamic).</summary>
    public bool ApplySla(SlaDecision decision, string explanationJson, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(decision);
        var changed = SlaDueAt != decision.DueAt || SlaRow != decision.Row || SlaPolicy != decision.Policy || SlaExplanation != explanationJson;
        SlaPolicy = decision.Policy;
        SlaRow = decision.Row;
        SlaDays = decision.Days;
        SlaStartedAt = decision.StartedAt;
        SlaDueAt = decision.DueAt;
        ForensicTriageRequired = decision.ForensicTriageRequired;
        SlaExplanation = explanationJson;
        if (changed)
        {
            UpdatedAt = now;
        }

        return changed;
    }
}

/// <summary>Append-only status history entry.</summary>
public sealed class FindingStatusChange
{
    private FindingStatusChange()
    {
    }

    public FindingStatusChange(
        Guid findingId,
        FindingStatus? fromStatus,
        FindingStatus toStatus,
        string? justification,
        Guid? vexStatementId,
        StatusChangeSource changeSource,
        string changedBy,
        DateTimeOffset changedAt)
    {
        FindingId = findingId;
        FromStatus = fromStatus;
        ToStatus = toStatus;
        Justification = justification;
        VexStatementId = vexStatementId;
        ChangeSource = changeSource;
        ChangedBy = changedBy;
        ChangedAt = changedAt;
    }

    public long Id { get; private set; }

    public Guid FindingId { get; private set; }

    public FindingStatus? FromStatus { get; private set; }

    public FindingStatus ToStatus { get; private set; }

    public string? Justification { get; private set; }

    public Guid? VexStatementId { get; private set; }

    public StatusChangeSource ChangeSource { get; private set; }

    public string ChangedBy { get; private set; } = string.Empty;

    public DateTimeOffset ChangedAt { get; private set; }
}
