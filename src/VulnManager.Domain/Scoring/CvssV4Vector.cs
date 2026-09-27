using System.Diagnostics.CodeAnalysis;

namespace VulnManager.Domain.Scoring;

/// <summary>
/// Parsed CVSS v4.0 vector. The base score is not computed locally (it needs the FIRST macro-vector lookup table),
/// so the score published by the source is used. The vector feeds the SSVC proxy (AU, VC, VI, VA).
/// </summary>
public sealed class CvssV4Vector
{
    private static readonly string[] RequiredBase = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];

    private readonly Dictionary<string, string> _metrics;

    private CvssV4Vector(Dictionary<string, string> metrics, string raw)
    {
        _metrics = metrics;
        Raw = raw;
    }

    public string Raw { get; }

    public string? this[string metric] => _metrics.GetValueOrDefault(metric);

    public static bool TryParse(string? vector, [NotNullWhen(true)] out CvssV4Vector? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(vector))
        {
            return false;
        }

        var parts = vector.Trim().Split('/');
        if (parts[0] != "CVSS:4.0")
        {
            return false;
        }

        var metrics = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in parts.Skip(1))
        {
            var pair = part.Split(':');
            if (pair.Length != 2 || pair[0].Length == 0 || pair[1].Length == 0 || !metrics.TryAdd(pair[0], pair[1]))
            {
                return false;
            }
        }

        if (!RequiredBase.All(metrics.ContainsKey))
        {
            return false;
        }

        parsed = new CvssV4Vector(metrics, vector.Trim());
        return true;
    }
}
