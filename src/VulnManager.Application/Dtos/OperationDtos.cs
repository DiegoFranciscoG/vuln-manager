using System.ComponentModel.DataAnnotations;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;
using VulnManager.Domain.Vex;

namespace VulnManager.Application.Dtos;

public sealed record VexStatementDto(
    Guid Id,
    Guid ProjectId,
    string VulnerabilityRef,
    string? ComponentPurl,
    VexStatus Status,
    VexJustificationScheme? JustificationScheme,
    string? Justification,
    string? ImpactStatement,
    string? ActionStatement,
    string? CdxState,
    VexSource Source,
    string Author,
    DateTimeOffset CreatedAt,
    DateTimeOffset? RevokedAt);

/// <summary>Manual VEX statement. Justifications use the CISA vocabulary.</summary>
public sealed class CreateVexStatementRequest
{
    [Required(ErrorMessage = "Indica el id de la vulnerabilidad.")]
    [StringLength(50)]
    [RegularExpression(@"^[A-Za-z0-9._:\-]+$", ErrorMessage = "Id de vulnerabilidad inválido.")]
    public string VulnerabilityRef { get; set; } = string.Empty;

    [StringLength(1000)]
    public string? ComponentPurl { get; set; }

    [EnumDataType(typeof(VexStatus))]
    public VexStatus Status { get; set; } = VexStatus.NotAffected;

    [StringLength(60)]
    public string? Justification { get; set; }

    [StringLength(VexStatementRules.MaxStatementLength)]
    public string? ImpactStatement { get; set; }

    [StringLength(VexStatementRules.MaxStatementLength)]
    public string? ActionStatement { get; set; }
}

public sealed record PriorityRuleDto(
    Guid Id,
    int Version,
    string Name,
    string? Notes,
    bool IsActive,
    decimal EpssPercentileThreshold,
    decimal HighImpactMinCvss,
    ImpactSignal UnknownSeverityAs,
    bool SsvcActiveCountsAsExploited,
    IReadOnlyList<PriorityRule> Rules,
    SlaPolicyType SlaPolicy,
    IReadOnlyDictionary<Severity, int> SlaSeverityDays,
    int? FixOnUpgradeDays,
    string CreatedBy,
    DateTimeOffset CreatedAt);

public sealed class CreatePriorityRuleRequest
{
    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Notes { get; set; }

    [Range(0.001, 1.0)]
    public decimal EpssPercentileThreshold { get; set; } = 0.90m;

    [Range(0.0, 10.0)]
    public decimal HighImpactMinCvss { get; set; } = 7.0m;

    [EnumDataType(typeof(ImpactSignal))]
    public ImpactSignal UnknownSeverityAs { get; set; } = ImpactSignal.High;

    public bool SsvcActiveCountsAsExploited { get; set; } = true;

    [Required]
    [MinLength(1)]
    [MaxLength(50)]
    public List<PriorityRule> Rules { get; set; } = [];

    [EnumDataType(typeof(SlaPolicyType))]
    public SlaPolicyType SlaPolicy { get; set; } = SlaPolicyType.Bod2604;

    public Dictionary<Severity, int>? SlaSeverityDays { get; set; }

    [Range(1, 3650)]
    public int? FixOnUpgradeDays { get; set; }

    public bool Activate { get; set; }
}

public sealed record AlertDto(
    Guid Id,
    Guid ProjectId,
    string ProjectName,
    Guid? FindingId,
    AlertType Type,
    string Message,
    DateTimeOffset CreatedAt,
    DateTimeOffset? AcknowledgedAt);

public sealed record SyncRunDto(
    Guid Id,
    SyncSource Source,
    SyncTrigger Trigger,
    SyncRunStatus Status,
    DateTimeOffset StartedAt,
    DateTimeOffset? FinishedAt,
    int ItemsRequested,
    int ItemsUpdated,
    int HttpRequests,
    int HttpThrottled,
    string? Watermark,
    string? ErrorMessage);

public sealed record AuditEntryDto(
    long Id,
    DateTimeOffset OccurredAt,
    ActorType ActorType,
    string ActorId,
    string Action,
    string EntityType,
    string EntityId,
    string? Details);

public sealed record DashboardDto(
    IReadOnlyList<ProjectSummaryDto> Projects,
    int OpenFindings,
    int P1,
    int Overdue,
    int InKev,
    int ForensicTriage,
    int OpenAlerts,
    IReadOnlyList<SyncRunDto> LatestSyncs);
