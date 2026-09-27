namespace VulnManager.Domain.Scoring;

/// <summary>CVSS v3.1 base score implemented from the FIRST specification (section 7 and Appendix A).</summary>
public static class CvssV31Calculator
{
    public static decimal BaseScore(CvssV3Vector vector)
    {
        ArgumentNullException.ThrowIfNull(vector);

        var scopeChanged = vector.ScopeChanged;
        var iss = 1 - ((1 - Cia(vector["C"])) * (1 - Cia(vector["I"])) * (1 - Cia(vector["A"])));

        var impact = scopeChanged
            ? (7.52 * (iss - 0.029)) - (3.25 * Math.Pow(iss - 0.02, 15))
            : 6.42 * iss;

        if (impact <= 0)
        {
            return 0.0m;
        }

        var exploitability = 8.22
            * AttackVector(vector["AV"])
            * AttackComplexity(vector["AC"])
            * PrivilegesRequired(vector["PR"], scopeChanged)
            * UserInteraction(vector["UI"]);

        var raw = scopeChanged
            ? Math.Min(1.08 * (impact + exploitability), 10)
            : Math.Min(impact + exploitability, 10);

        return (decimal)Roundup(raw);
    }

    /// <summary>Smallest number, to one decimal place, equal to or higher than the input. Integer arithmetic avoids floating point drift.</summary>
    public static double Roundup(double input)
    {
        var intInput = (long)Math.Round(input * 100_000);
        if (intInput % 10_000 == 0)
        {
            return intInput / 100_000.0;
        }

        return (Math.Floor(intInput / 10_000.0) + 1) / 10.0;
    }

    private static double AttackVector(string value) => value switch
    {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown AV value."),
    };

    private static double AttackComplexity(string value) => value switch
    {
        "L" => 0.77,
        "H" => 0.44,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown AC value."),
    };

    private static double PrivilegesRequired(string value, bool scopeChanged) => value switch
    {
        "N" => 0.85,
        "L" => scopeChanged ? 0.68 : 0.62,
        "H" => scopeChanged ? 0.5 : 0.27,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown PR value."),
    };

    private static double UserInteraction(string value) => value switch
    {
        "N" => 0.85,
        "R" => 0.62,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown UI value."),
    };

    private static double Cia(string value) => value switch
    {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0,
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown impact value."),
    };
}
