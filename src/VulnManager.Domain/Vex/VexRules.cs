using VulnManager.Domain.Packages;

namespace VulnManager.Domain.Vex;

/// <summary>VEX status values from CISA "Minimum Requirements for VEX" (April 2023).</summary>
public enum VexStatus
{
    NotAffected = 0,
    Affected = 1,
    Fixed = 2,
    UnderInvestigation = 3,
}

/// <summary>Vocabulary of the justification: CISA (manual statements) or CycloneDX 1.7 (imported statements).</summary>
public enum VexJustificationScheme
{
    Cisa = 0,
    CycloneDx = 1,
}

public static class VexJustifications
{
    /// <summary>CISA status justifications for "not_affected".</summary>
    public static IReadOnlySet<string> Cisa { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    };

    /// <summary>CycloneDX 1.7 impactAnalysisJustification enum.</summary>
    public static IReadOnlySet<string> CycloneDx { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    };

    public static bool IsValid(VexJustificationScheme scheme, string justification) => scheme switch
    {
        VexJustificationScheme.Cisa => Cisa.Contains(justification),
        VexJustificationScheme.CycloneDx => CycloneDx.Contains(justification),
        _ => false,
    };
}

public sealed record VexStatementDraft(
    VexStatus Status,
    VexJustificationScheme? JustificationScheme,
    string? Justification,
    string? ImpactStatement,
    string? ActionStatement,
    string VulnerabilityRef,
    string? ComponentPurl);

public static class VexStatementRules
{
    public const int MaxStatementLength = 2000;

    /// <summary>
    /// CISA: "not_affected" MUST carry a justification or, failing that, an impact statement;
    /// "affected" MUST carry an action statement.
    /// </summary>
    public static IReadOnlyList<string> Validate(VexStatementDraft draft)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(draft.VulnerabilityRef) || draft.VulnerabilityRef.Length > 50)
        {
            errors.Add("Indica el id de la vulnerabilidad (CVE o GHSA, máximo 50 caracteres).");
        }

        if (draft.ComponentPurl is not null && !PackageUrl.TryParse(draft.ComponentPurl, out _))
        {
            errors.Add("El PURL del componente no es válido.");
        }

        if (draft.Justification is not null)
        {
            if (draft.JustificationScheme is not { } scheme)
            {
                errors.Add("Indica el vocabulario de la justificación (CISA o CycloneDX).");
            }
            else if (!VexJustifications.IsValid(scheme, draft.Justification))
            {
                errors.Add($"Justificación '{draft.Justification}' no válida para el vocabulario {scheme}.");
            }
        }

        if (draft.ImpactStatement?.Length > MaxStatementLength || draft.ActionStatement?.Length > MaxStatementLength)
        {
            errors.Add($"Las declaraciones admiten como máximo {MaxStatementLength} caracteres.");
        }

        switch (draft.Status)
        {
            case VexStatus.NotAffected when draft.Justification is null && string.IsNullOrWhiteSpace(draft.ImpactStatement):
                errors.Add("'not_affected' requiere una justificación o una declaración de impacto (CISA VEX).");
                break;
            case VexStatus.Affected when string.IsNullOrWhiteSpace(draft.ActionStatement):
                errors.Add("'affected' requiere una declaración de acción (CISA VEX).");
                break;
        }

        return errors;
    }
}
