using System.Globalization;
using VulnManager.Domain.Common;
using VulnManager.Domain.Scoring;

namespace VulnManager.Domain.Prioritization;

/// <summary>
/// Evaluates the decision table. Signals are normalized first (KEV/SSVC, EPSS percentile, CVSS/severity, exposure)
/// and never multiplied together, following FIRST guidance on EPSS and CISA SSVC decision trees.
/// </summary>
public static class PriorityEngine
{
    public static PriorityDecision Evaluate(PriorityRuleSet ruleSet, PriorityInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(inputs);

        var (exploitation, sources) = ResolveExploitation(ruleSet, inputs);
        var impact = ResolveImpact(ruleSet, inputs);

        var rule = ruleSet.Rules.FirstOrDefault(r => r.When.Matches(exploitation, impact, inputs.Exposure))
            ?? throw new DomainException("La regla de prioridad no cubre todas las combinaciones de señales.");

        return new PriorityDecision(rule.Level, rule.Id, exploitation, impact, sources, BuildReasons(rule, inputs, exploitation, impact, ruleSet));
    }

    public static ExploitationSignal ResolveExploitationSignal(PriorityRuleSet ruleSet, PriorityInputs inputs) =>
        ResolveExploitation(ruleSet, inputs).Signal;

    public static ImpactSignal ResolveImpact(PriorityRuleSet ruleSet, PriorityInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(inputs);

        if (inputs.CvssScore is { } score)
        {
            return score >= ruleSet.HighImpactMinCvss ? ImpactSignal.High : ImpactSignal.Low;
        }

        return inputs.Severity switch
        {
            Severity.Critical or Severity.High => ImpactSignal.High,
            Severity.Medium or Severity.Low or Severity.None => ImpactSignal.Low,
            _ => ruleSet.UnknownSeverityAs,
        };
    }

    private static (ExploitationSignal Signal, IReadOnlyList<string> Sources) ResolveExploitation(PriorityRuleSet ruleSet, PriorityInputs inputs)
    {
        var sources = new List<string>();
        if (inputs.InKev)
        {
            sources.Add("KEV");
        }

        if (ruleSet.SsvcActiveCountsAsExploited && inputs.SsvcExploitation == SsvcExploitation.Active)
        {
            sources.Add("SSVC:active");
        }

        if (sources.Count > 0)
        {
            return (ExploitationSignal.Active, sources);
        }

        if (inputs.EpssPercentile is { } percentile && percentile >= ruleSet.EpssPercentileThreshold)
        {
            return (ExploitationSignal.Likely, ["EPSS"]);
        }

        return (ExploitationSignal.None, []);
    }

    private static List<string> BuildReasons(PriorityRule rule, PriorityInputs inputs, ExploitationSignal exploitation, ImpactSignal impact, PriorityRuleSet ruleSet)
    {
        var culture = CultureInfo.InvariantCulture;
        var reasons = new List<string> { $"{rule.Id}: {rule.Reason}" };

        if (inputs.InKev)
        {
            var since = inputs.KevDateAdded is { } date ? $" desde {date.ToString("yyyy-MM-dd", culture)}" : string.Empty;
            reasons.Add($"En el catálogo KEV de CISA{since}");
            if (inputs.KnownRansomwareUse)
            {
                reasons.Add("Usada en campañas de ransomware (KEV)");
            }
        }

        if (inputs.SsvcExploitation == SsvcExploitation.Active)
        {
            reasons.Add("CISA Vulnrichment reporta explotación activa (SSVC)");
        }

        reasons.Add(inputs.EpssPercentile is { } percentile
            ? string.Format(culture, "EPSS percentil {0:0.000} (umbral {1:0.000}){2}", percentile, ruleSet.EpssPercentileThreshold,
                exploitation == ExploitationSignal.Likely ? ": probable explotación en 30 días" : string.Empty)
            : "Sin dato EPSS (el aviso no tiene CVE o EPSS no lo puntúa)");

        reasons.Add(inputs.CvssScore is { } cvss
            ? string.Format(culture, "CVSS {0:0.0} ({1}): impacto {2}", cvss, inputs.Severity, impact == ImpactSignal.High ? "alto" : "limitado")
            : $"Sin puntaje CVSS; severidad {inputs.Severity}: impacto {(impact == ImpactSignal.High ? "alto" : "limitado")}");

        reasons.Add(inputs.Exposure == Exposure.Public ? "Proyecto expuesto públicamente" : "Proyecto interno");

        reasons.Add(inputs.FixAvailable
            ? $"Parche disponible{(inputs.SuggestedFixVersion is null ? string.Empty : $": actualizar a {inputs.SuggestedFixVersion}")}"
            : "Sin parche publicado: mitigar o aceptar el riesgo");

        return reasons;
    }
}
