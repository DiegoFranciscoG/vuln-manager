namespace VulnManager.Domain.Findings;

public enum FindingStatus
{
    New = 0,

    /// <summary>Risk accepted until a date (assumption S1).</summary>
    Accepted = 1,

    Mitigated = 2,
    FalsePositive = 3,

    /// <summary>A VEX statement declares the product not affected.</summary>
    NotAffected = 4,

    /// <summary>Closed by the system: component removed or upgraded, VEX "fixed" or advisory withdrawn.</summary>
    Fixed = 5,
}

public enum StatusChangeSource
{
    User = 0,
    SbomImport = 1,
    Vex = 2,
    Sync = 3,
    Expiry = 4,
}

public sealed record TransitionRequest(
    FindingStatus From,
    FindingStatus To,
    StatusChangeSource Source,
    string? Justification,
    DateOnly? RiskAcceptedUntil,
    DateOnly Today,
    int MaxAcceptanceDays);

/// <summary>Allowed status transitions (docs/modelo-datos.md section 3.3). Returns the list of violated rules; empty means allowed.</summary>
public static class FindingTransitions
{
    public const int MinJustificationLength = 10;
    public const int MaxJustificationLength = 1000;

    public static bool IsOpen(FindingStatus status) => status == FindingStatus.New;

    public static IReadOnlyList<string> Check(TransitionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var errors = new List<string>();

        if (request.From == request.To)
        {
            errors.Add($"El hallazgo ya está en estado {request.To}.");
            return errors;
        }

        if (!IsAllowed(request.From, request.To, request.Source))
        {
            errors.Add($"Transición no permitida: {request.From} → {request.To} ({request.Source}).");
            return errors;
        }

        if (request.Source == StatusChangeSource.User)
        {
            var length = request.Justification?.Trim().Length ?? 0;
            if (length < MinJustificationLength)
            {
                errors.Add($"La justificación es obligatoria (mínimo {MinJustificationLength} caracteres).");
            }
            else if (length > MaxJustificationLength)
            {
                errors.Add($"La justificación admite como máximo {MaxJustificationLength} caracteres.");
            }
        }

        if (request.To == FindingStatus.Accepted)
        {
            if (request.RiskAcceptedUntil is not { } until)
            {
                errors.Add("Aceptar el riesgo requiere una fecha de expiración.");
            }
            else if (until <= request.Today || until > request.Today.AddDays(request.MaxAcceptanceDays))
            {
                errors.Add($"La aceptación de riesgo debe vencer entre mañana y {request.MaxAcceptanceDays} días.");
            }
        }

        return errors;
    }

    private static bool IsAllowed(FindingStatus from, FindingStatus to, StatusChangeSource source) => source switch
    {
        StatusChangeSource.User => (from, to) switch
        {
            (FindingStatus.New, FindingStatus.Accepted or FindingStatus.Mitigated or FindingStatus.FalsePositive) => true,
            (FindingStatus.Accepted or FindingStatus.Mitigated or FindingStatus.FalsePositive or FindingStatus.NotAffected, FindingStatus.New) => true,
            _ => false,
        },
        StatusChangeSource.Vex => (from, to) switch
        {
            (not FindingStatus.Fixed, FindingStatus.NotAffected or FindingStatus.Fixed or FindingStatus.FalsePositive) => true,
            (FindingStatus.NotAffected, FindingStatus.New) => true,
            _ => false,
        },
        StatusChangeSource.SbomImport => (from, to) switch
        {
            (not FindingStatus.Fixed, FindingStatus.Fixed) => true,
            (FindingStatus.Fixed, FindingStatus.New) => true,
            _ => false,
        },
        StatusChangeSource.Sync => from != FindingStatus.Fixed && to == FindingStatus.Fixed,
        StatusChangeSource.Expiry => from == FindingStatus.Accepted && to == FindingStatus.New,
        _ => false,
    };
}
