using System.Globalization;
using System.Text;
using VulnManager.Application.Dtos;

namespace VulnManager.Application.Services;

/// <summary>
/// RFC 4180 CSV with OWASP CSV-injection protection: cells starting with =, +, -, @, TAB, CR or LF get a leading
/// single quote, every cell is quoted and inner quotes are doubled.
/// </summary>
public static class CsvWriter
{
    private static readonly string[] Header =
    [
        "finding_id", "project", "component_purl", "vulnerability_id", "cve_id", "severity", "cvss", "epss", "epss_percentile",
        "in_kev", "priority", "status", "fix_available", "suggested_fix", "sla_due_at", "overdue", "forensic_triage", "first_detected_at",
    ];

    public static string Write(IEnumerable<FindingListItemDto> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        var builder = new StringBuilder();
        AppendRow(builder, Header);
        foreach (var r in rows)
        {
            AppendRow(builder,
            [
                r.Id.ToString(),
                r.ProjectName,
                r.ComponentPurl,
                r.VulnerabilityId,
                r.CveId ?? string.Empty,
                Upper(r.Severity.ToString()),
                Format(r.CvssScore),
                Format(r.EpssScore),
                Format(r.EpssPercentile),
                r.InKev ? "true" : "false",
                r.Priority.ToString(),
                Upper(r.Status.ToString()),
                r.FixAvailable ? "true" : "false",
                r.SuggestedFixVersion ?? string.Empty,
                r.SlaDueAt?.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) ?? string.Empty,
                r.Overdue ? "true" : "false",
                r.ForensicTriageRequired ? "true" : "false",
                r.FirstDetectedAt.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ]);
        }

        return builder.ToString();
    }

    public static string Escape(string? value)
    {
        var text = value ?? string.Empty;
        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n')
        {
            text = "'" + text;
        }

        return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static void AppendRow(StringBuilder builder, IEnumerable<string> cells) =>
        builder.AppendJoin(',', cells.Select(Escape)).Append("\r\n");

    private static string Format(decimal? value) => value?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;

    private static string Upper(string pascal) =>
        string.Concat(pascal.Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + c : c.ToString())).ToUpperInvariant();
}
