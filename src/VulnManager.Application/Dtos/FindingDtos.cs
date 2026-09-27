using System.ComponentModel.DataAnnotations;
using VulnManager.Domain.Common;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;

namespace VulnManager.Application.Dtos;

public enum FindingSort
{
    Priority = 0,
    SlaDue = 1,
    Cvss = 2,
    Epss = 3,
    Detected = 4,
}

public sealed class FindingQuery
{
    public Guid? ProjectId { get; set; }

    public IReadOnlyCollection<FindingStatus>? Statuses { get; set; }

    public IReadOnlyCollection<PriorityLevel>? Priorities { get; set; }

    public IReadOnlyCollection<Severity>? Severities { get; set; }

    public bool? InKev { get; set; }

    public bool? Overdue { get; set; }

    public bool? FixAvailable { get; set; }

    [StringLength(100)]
    public string? Search { get; set; }

    [Range(1, 10_000)]
    public int Page { get; set; } = 1;

    [Range(1, 200)]
    public int PageSize { get; set; } = 25;

    public FindingSort Sort { get; set; } = FindingSort.Priority;
}

public sealed record FindingListItemDto(
    Guid Id,
    Guid ProjectId,
    string ProjectName,
    string ComponentPurl,
    string ComponentName,
    string ComponentVersion,
    string VulnerabilityId,
    string? CveId,
    string? Summary,
    Severity Severity,
    decimal? CvssScore,
    decimal? EpssScore,
    decimal? EpssPercentile,
    bool InKev,
    bool KnownRansomware,
    FindingStatus Status,
    PriorityLevel Priority,
    bool FixAvailable,
    string? SuggestedFixVersion,
    DateTimeOffset? SlaDueAt,
    int? SlaDaysRemaining,
    bool Overdue,
    bool ForensicTriageRequired,
    DateTimeOffset FirstDetectedAt);

public sealed record FindingHistoryDto(
    FindingStatus? From,
    FindingStatus To,
    string? Justification,
    StatusChangeSource Source,
    string ChangedBy,
    DateTimeOffset ChangedAt);

public sealed record FindingDetailDto(
    FindingListItemDto Summary,
    IReadOnlyList<string> Aliases,
    string? Details,
    string? CvssVersion,
    string? CvssVector,
    string? CvssSource,
    SsvcExploitation? SsvcExploitation,
    bool? SsvcAutomatable,
    TechnicalImpact? SsvcTechnicalImpact,
    DateOnly? EpssDate,
    DateOnly? KevDateAdded,
    DateOnly? KevDueDate,
    string? KevRequiredAction,
    IReadOnlyList<string> FixedVersions,
    string? StatusReason,
    DateOnly? RiskAcceptedUntil,
    Guid? VexStatementId,
    PriorityExplanationDto? PriorityExplanation,
    SlaExplanationDto? SlaExplanation,
    IReadOnlyList<FindingHistoryDto> History);

public sealed class ChangeFindingStatusRequest
{
    [EnumDataType(typeof(FindingStatus))]
    public FindingStatus Status { get; set; }

    [StringLength(FindingTransitions.MaxJustificationLength)]
    public string? Justification { get; set; }

    public DateOnly? RiskAcceptedUntil { get; set; }
}

public sealed record PriorityInputsDto(
    ExploitationSignal Exploitation,
    IReadOnlyList<string> ExploitationSources,
    decimal? EpssPercentile,
    decimal EpssThreshold,
    Severity Severity,
    decimal? CvssScore,
    string? CvssVersion,
    ImpactSignal Impact,
    Exposure Exposure,
    bool FixAvailable,
    string? SuggestedFixVersion);

public sealed record PriorityExplanationDto(int RuleVersion, string MatchedRule, PriorityLevel Level, PriorityInputsDto Inputs, IReadOnlyList<string> Reasons);

public sealed record SlaExplanationDto(
    SlaPolicyType Policy,
    int? Row,
    int? Days,
    DateTimeOffset StartedAt,
    string StartBasis,
    DateTimeOffset? DueAt,
    bool ForensicTriage,
    bool PubliclyExposed,
    bool InKev,
    bool? Automatable,
    SsvcDataSource? AutomatableSource,
    TechnicalImpact? TechnicalImpact,
    SsvcDataSource? TechnicalImpactSource,
    Severity Severity);
