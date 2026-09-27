using VulnManager.Domain.Common;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;

namespace VulnManager.Domain.Entities;

/// <summary>Immutable, versioned priority rule set plus SLA policy. Exactly one version is active.</summary>
public sealed class PriorityRuleVersion
{
    private PriorityRuleVersion()
    {
    }

    public PriorityRuleVersion(int version, string name, string? notes, PriorityRuleSet ruleSet, SlaSettings sla, string createdBy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(sla);
        PriorityRuleSetValidator.EnsureValid(ruleSet);

        if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
        {
            throw new DomainException("El nombre de la regla es obligatorio (máximo 100 caracteres).");
        }

        if (notes?.Length > 500)
        {
            throw new DomainException("Las notas admiten como máximo 500 caracteres.");
        }

        if (sla.FixOnUpgradeDays is <= 0 or > 3650 || sla.SeverityDays.Values.Any(d => d is <= 0 or > 3650))
        {
            throw new DomainException("Los plazos de SLA deben estar entre 1 y 3650 días.");
        }

        Id = Guid.CreateVersion7(now);
        Version = version;
        Name = name.Trim();
        Notes = notes;
        EpssPercentileThreshold = ruleSet.EpssPercentileThreshold;
        HighImpactMinCvss = ruleSet.HighImpactMinCvss;
        UnknownSeverityAs = ruleSet.UnknownSeverityAs;
        SsvcActiveCountsAsExploited = ruleSet.SsvcActiveCountsAsExploited;
        Rules = ruleSet.Rules.ToList();
        SlaPolicy = sla.Policy;
        SlaSeverityDays = new Dictionary<Severity, int>(sla.SeverityDays);
        FixOnUpgradeDays = sla.FixOnUpgradeDays;
        CreatedBy = createdBy;
        CreatedAt = now;
    }

    public Guid Id { get; private set; }

    public int Version { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string? Notes { get; private set; }

    public bool IsActive { get; private set; }

    public decimal EpssPercentileThreshold { get; private set; }

    public decimal HighImpactMinCvss { get; private set; }

    public ImpactSignal UnknownSeverityAs { get; private set; }

    public bool SsvcActiveCountsAsExploited { get; private set; }

    public IReadOnlyList<PriorityRule> Rules { get; private set; } = [];

    public SlaPolicyType SlaPolicy { get; private set; }

    public IReadOnlyDictionary<Severity, int> SlaSeverityDays { get; private set; } = new Dictionary<Severity, int>();

    public int? FixOnUpgradeDays { get; private set; }

    public string CreatedBy { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public PriorityRuleSet ToRuleSet() => new(EpssPercentileThreshold, HighImpactMinCvss, UnknownSeverityAs, SsvcActiveCountsAsExploited, Rules);

    public SlaSettings ToSlaSettings() => new(SlaPolicy, SlaSeverityDays, FixOnUpgradeDays);

    public void Activate() => IsActive = true;

    public void Deactivate() => IsActive = false;
}
