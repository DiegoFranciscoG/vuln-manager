using VulnManager.Domain.Common;
using VulnManager.Domain.Scoring;

namespace VulnManager.Domain.Sla;

public enum SlaPolicyType
{
    /// <summary>CISA BOD 26-04 Table 1 (default).</summary>
    Bod2604 = 0,

    /// <summary>Fixed days per severity (assumption S4).</summary>
    Severity = 1,
}

public sealed record SlaSettings(SlaPolicyType Policy, IReadOnlyDictionary<Severity, int> SeverityDays, int? FixOnUpgradeDays)
{
    public static IReadOnlyDictionary<Severity, int> DefaultSeverityDays { get; } = new Dictionary<Severity, int>
    {
        [Severity.Critical] = 15,
        [Severity.High] = 30,
        [Severity.Medium] = 90,
        [Severity.Low] = 180,
    };

    public static SlaSettings Default { get; } = new(SlaPolicyType.Bod2604, DefaultSeverityDays, null);
}

public sealed record SlaInputs(
    Exposure Exposure,
    bool InKev,
    DateOnly? KevDateAdded,
    bool? CisaAutomatable,
    TechnicalImpact? CisaTechnicalImpact,
    string? CvssVector,
    Severity Severity,
    DateTimeOffset FirstDetectedAt);

public sealed record SlaDecision(
    SlaPolicyType Policy,
    int? Row,
    int? Days,
    DateTimeOffset StartedAt,
    string StartBasis,
    DateTimeOffset? DueAt,
    bool ForensicTriageRequired,
    SsvcFacts? Ssvc);

public static class SlaCalculator
{
    public const string StartBasisDetection = "DETECTION";
    public const string StartBasisKev = "KEV_DATE_ADDED";

    /// <summary>
    /// BOD 26-04: the timeline starts at the earliest of "added to KEV" and "vulnerability identified on the asset",
    /// and it is dynamic: recalculating with new facts (KEV addition, exposure change) yields the new deadline.
    /// </summary>
    public static SlaDecision Calculate(SlaSettings settings, SlaInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(inputs);

        var (startedAt, basis) = ResolveStart(inputs);

        if (settings.Policy == SlaPolicyType.Severity)
        {
            var severity = inputs.Severity is Severity.Unknown or Severity.None ? Severity.High : inputs.Severity;
            int? days = settings.SeverityDays.TryGetValue(severity, out var d) ? d : null;
            return new SlaDecision(SlaPolicyType.Severity, null, days, startedAt, basis, days is null ? null : startedAt.AddDays(days.Value), false, null);
        }

        var ssvc = SsvcProxy.Resolve(inputs.CisaAutomatable, inputs.CisaTechnicalImpact, inputs.CvssVector);
        var row = Bod2604Timeline.Lookup(inputs.Exposure == Exposure.Public, inputs.InKev, ssvc.Automatable, ssvc.TechnicalImpact);
        var effectiveDays = row.Days ?? settings.FixOnUpgradeDays;
        DateTimeOffset? dueAt = effectiveDays is null ? null : startedAt.AddDays(effectiveDays.Value);

        return new SlaDecision(SlaPolicyType.Bod2604, row.Number, effectiveDays, startedAt, basis, dueAt, row.ForensicTriage, ssvc);
    }

    private static (DateTimeOffset StartedAt, string Basis) ResolveStart(SlaInputs inputs)
    {
        if (inputs.InKev && inputs.KevDateAdded is { } added)
        {
            var kevStart = new DateTimeOffset(added.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
            if (kevStart < inputs.FirstDetectedAt)
            {
                return (kevStart, StartBasisKev);
            }
        }

        return (inputs.FirstDetectedAt, StartBasisDetection);
    }
}
