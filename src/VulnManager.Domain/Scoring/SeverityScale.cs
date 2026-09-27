namespace VulnManager.Domain.Scoring;

public static class SeverityScale
{
    /// <summary>Maps a CVSS base score to its rating: None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0.</summary>
    public static Severity FromScore(decimal score)
    {
        if (score is < 0m or > 10m)
        {
            throw new ArgumentOutOfRangeException(nameof(score), score, "CVSS scores range from 0.0 to 10.0.");
        }

        return score switch
        {
            0m => Severity.None,
            < 4.0m => Severity.Low,
            < 7.0m => Severity.Medium,
            < 9.0m => Severity.High,
            _ => Severity.Critical,
        };
    }

    /// <summary>Maps textual severities published by advisory databases (for example GHSA "MODERATE").</summary>
    public static Severity FromText(string? text) => text?.Trim().ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH" => Severity.High,
        "MODERATE" or "MEDIUM" => Severity.Medium,
        "LOW" => Severity.Low,
        "NONE" => Severity.None,
        _ => Severity.Unknown,
    };
}
