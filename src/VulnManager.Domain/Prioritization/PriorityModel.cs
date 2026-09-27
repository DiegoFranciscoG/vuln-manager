using VulnManager.Domain.Common;
using VulnManager.Domain.Scoring;

namespace VulnManager.Domain.Prioritization;

public enum PriorityLevel
{
    P1 = 1,
    P2 = 2,
    P3 = 3,
    P4 = 4,
}

/// <summary>Normalized exploitation evidence: confirmed (KEV or SSVC active), likely (EPSS percentile) or none known.</summary>
public enum ExploitationSignal
{
    None = 0,
    Likely = 1,
    Active = 2,
}

public enum ImpactSignal
{
    Low = 0,
    High = 1,
}

/// <summary>Condition of a rule. A null list means "any value".</summary>
public sealed record PriorityCondition(
    IReadOnlyList<ExploitationSignal>? Exploitation = null,
    IReadOnlyList<ImpactSignal>? Impact = null,
    IReadOnlyList<Exposure>? Exposure = null)
{
    public bool Matches(ExploitationSignal exploitation, ImpactSignal impact, Exposure exposure) =>
        (Exploitation is null || Exploitation.Contains(exploitation))
        && (Impact is null || Impact.Contains(impact))
        && (Exposure is null || Exposure.Contains(exposure));
}

public sealed record PriorityRule(string Id, PriorityCondition When, PriorityLevel Level, string Reason);

/// <summary>A versioned, configurable decision table. The first matching rule wins.</summary>
public sealed record PriorityRuleSet(
    decimal EpssPercentileThreshold,
    decimal HighImpactMinCvss,
    ImpactSignal UnknownSeverityAs,
    bool SsvcActiveCountsAsExploited,
    IReadOnlyList<PriorityRule> Rules)
{
    /// <summary>Version 1 shipped with the product (docs/modelo-datos.md section 3.1).</summary>
    public static PriorityRuleSet Default { get; } = new(
        EpssPercentileThreshold: 0.90m,
        HighImpactMinCvss: 7.0m,
        UnknownSeverityAs: ImpactSignal.High,
        SsvcActiveCountsAsExploited: true,
        Rules:
        [
            new("R1", new([ExploitationSignal.Active], null, [Exposure.Public]), PriorityLevel.P1,
                "Explotación confirmada en un servicio expuesto a Internet"),
            new("R2", new([ExploitationSignal.Active], [ImpactSignal.High]), PriorityLevel.P1,
                "Explotación confirmada con impacto alto"),
            new("R3", new([ExploitationSignal.Active]), PriorityLevel.P2,
                "Explotación confirmada con impacto limitado en un servicio interno"),
            new("R4", new([ExploitationSignal.Likely], [ImpactSignal.High]), PriorityLevel.P2,
                "Probabilidad de explotación alta (EPSS) con impacto alto"),
            new("R5", new([ExploitationSignal.Likely]), PriorityLevel.P3,
                "Probabilidad de explotación alta (EPSS) con impacto limitado"),
            new("R6", new([ExploitationSignal.None], [ImpactSignal.High], [Exposure.Public]), PriorityLevel.P3,
                "Sin señal de explotación, pero impacto alto en un servicio expuesto"),
            new("R7", new(), PriorityLevel.P4, "Sin señales de urgencia"),
        ]);
}

/// <summary>Facts about one finding that feed the decision table.</summary>
public sealed record PriorityInputs(
    bool InKev,
    DateOnly? KevDateAdded,
    bool KnownRansomwareUse,
    SsvcExploitation? SsvcExploitation,
    decimal? EpssScore,
    decimal? EpssPercentile,
    Severity Severity,
    decimal? CvssScore,
    Exposure Exposure,
    bool FixAvailable,
    string? SuggestedFixVersion);

public sealed record PriorityDecision(
    PriorityLevel Level,
    string MatchedRuleId,
    ExploitationSignal Exploitation,
    ImpactSignal Impact,
    IReadOnlyList<string> ExploitationSources,
    IReadOnlyList<string> Reasons);
