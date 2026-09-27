using System.Diagnostics.CodeAnalysis;

namespace VulnManager.Domain.Scoring;

/// <summary>Parsed CVSS v3.0/v3.1 vector. Temporal and environmental metrics are accepted but ignored for the base score.</summary>
public sealed class CvssV3Vector
{
    private static readonly string[] BaseMetrics = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

    private static readonly Dictionary<string, string[]> AllowedValues = new(StringComparer.Ordinal)
    {
        ["AV"] = ["N", "A", "L", "P"],
        ["AC"] = ["L", "H"],
        ["PR"] = ["N", "L", "H"],
        ["UI"] = ["N", "R"],
        ["S"] = ["U", "C"],
        ["C"] = ["H", "L", "N"],
        ["I"] = ["H", "L", "N"],
        ["A"] = ["H", "L", "N"],
        ["E"] = ["X", "H", "F", "P", "U"],
        ["RL"] = ["X", "U", "W", "T", "O"],
        ["RC"] = ["X", "C", "R", "U"],
        ["CR"] = ["X", "H", "M", "L"],
        ["IR"] = ["X", "H", "M", "L"],
        ["AR"] = ["X", "H", "M", "L"],
        ["MAV"] = ["X", "N", "A", "L", "P"],
        ["MAC"] = ["X", "L", "H"],
        ["MPR"] = ["X", "N", "L", "H"],
        ["MUI"] = ["X", "N", "R"],
        ["MS"] = ["X", "U", "C"],
        ["MC"] = ["X", "H", "L", "N"],
        ["MI"] = ["X", "H", "L", "N"],
        ["MA"] = ["X", "H", "L", "N"],
    };

    private readonly Dictionary<string, string> _metrics;

    private CvssV3Vector(string version, Dictionary<string, string> metrics, string raw)
    {
        Version = version;
        _metrics = metrics;
        Raw = raw;
    }

    /// <summary>"3.0" or "3.1".</summary>
    public string Version { get; }

    public string Raw { get; }

    public string this[string metric] => _metrics[metric];

    public bool ScopeChanged => _metrics["S"] == "C";

    public static CvssV3Vector Parse(string vector) =>
        TryParse(vector, out var parsed) ? parsed : throw new FormatException($"Invalid CVSS v3 vector: '{vector}'.");

    public static bool TryParse(string? vector, [NotNullWhen(true)] out CvssV3Vector? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(vector))
        {
            return false;
        }

        var parts = vector.Trim().Split('/');
        var version = parts[0] switch
        {
            "CVSS:3.1" => "3.1",
            "CVSS:3.0" => "3.0",
            _ => null,
        };
        if (version is null)
        {
            return false;
        }

        var metrics = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in parts.Skip(1))
        {
            var pair = part.Split(':');
            if (pair.Length != 2
                || !AllowedValues.TryGetValue(pair[0], out var allowed)
                || !allowed.Contains(pair[1])
                || !metrics.TryAdd(pair[0], pair[1]))
            {
                return false;
            }
        }

        if (!BaseMetrics.All(metrics.ContainsKey))
        {
            return false;
        }

        parsed = new CvssV3Vector(version, metrics, vector.Trim());
        return true;
    }
}
