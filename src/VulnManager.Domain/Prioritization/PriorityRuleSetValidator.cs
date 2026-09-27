using VulnManager.Domain.Common;

namespace VulnManager.Domain.Prioritization;

/// <summary>A rule set is only accepted if it is exhaustive over the 12 signal combinations and has no unreachable rules.</summary>
public static class PriorityRuleSetValidator
{
    public static IReadOnlyList<string> Validate(PriorityRuleSet ruleSet)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        var errors = new List<string>();

        if (ruleSet.EpssPercentileThreshold is <= 0m or > 1m)
        {
            errors.Add("El umbral de percentil EPSS debe estar en (0, 1].");
        }

        if (ruleSet.HighImpactMinCvss is < 0m or > 10m)
        {
            errors.Add("El corte de CVSS para impacto alto debe estar entre 0 y 10.");
        }

        if (ruleSet.Rules.Count is 0 or > 50)
        {
            errors.Add("La tabla debe tener entre 1 y 50 reglas.");
            return errors;
        }

        foreach (var duplicate in ruleSet.Rules.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        {
            errors.Add($"Id de regla duplicado: {duplicate.Key}.");
        }

        foreach (var rule in ruleSet.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.Id) || rule.Id.Length > 20)
            {
                errors.Add("Cada regla necesita un id de 1 a 20 caracteres.");
            }

            if (string.IsNullOrWhiteSpace(rule.Reason) || rule.Reason.Length > 200)
            {
                errors.Add($"La regla {rule.Id} necesita una explicación de 1 a 200 caracteres.");
            }

            if (!Enum.IsDefined(rule.Level))
            {
                errors.Add($"La regla {rule.Id} tiene un nivel inválido.");
            }

            if (rule.When.Exploitation is { Count: 0 } || rule.When.Impact is { Count: 0 } || rule.When.Exposure is { Count: 0 })
            {
                errors.Add($"La regla {rule.Id} tiene una condición vacía: omítela para indicar 'cualquiera'.");
            }
        }

        var reached = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var combination in AllCombinations())
        {
            var first = ruleSet.Rules.FirstOrDefault(r => r.When.Matches(combination.Exploitation, combination.Impact, combination.Exposure));
            if (first is null)
            {
                errors.Add($"Ninguna regla cubre: explotación {combination.Exploitation}, impacto {combination.Impact}, exposición {combination.Exposure}.");
            }
            else
            {
                reached.Add(first.Id);
            }
        }

        foreach (var unreachable in ruleSet.Rules.Where(r => !reached.Contains(r.Id)))
        {
            errors.Add($"La regla {unreachable.Id} nunca se aplica porque reglas anteriores cubren todos sus casos.");
        }

        return errors;
    }

    public static void EnsureValid(PriorityRuleSet ruleSet)
    {
        var errors = Validate(ruleSet);
        if (errors.Count > 0)
        {
            throw new DomainException(string.Join(" ", errors));
        }
    }

    public static IEnumerable<(ExploitationSignal Exploitation, ImpactSignal Impact, Exposure Exposure)> AllCombinations() =>
        from exploitation in Enum.GetValues<ExploitationSignal>()
        from impact in Enum.GetValues<ImpactSignal>()
        from exposure in Enum.GetValues<Exposure>()
        select (exploitation, impact, exposure);
}
