using System.ComponentModel.DataAnnotations;

namespace VulnManager.Infrastructure.External;

/// <summary>Endpoints and published limits of the external sources (docs/investigacion.md #1-#26).</summary>
public sealed class ExternalSourcesOptions
{
    public const string Section = "ExternalSources";

    [Required]
    public Uri OsvBaseUrl { get; set; } = new("https://api.osv.dev/");

    [Required]
    public Uri KevFeedUrl { get; set; } = new("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");

    [Required]
    public Uri EpssBaseUrl { get; set; } = new("https://api.first.org/");

    [Required]
    public Uri CveServicesBaseUrl { get; set; } = new("https://cveawg.mitre.org/");

    [Required]
    public Uri NvdBaseUrl { get; set; } = new("https://services.nvd.nist.gov/");

    /// <summary>Optional NVD API key (sent in the "apiKey" header, never logged). Raises the limit from 5 to 50 per 30 s.</summary>
    public string? NvdApiKey { get; set; }

    /// <summary>NVD rolling window (30 s) and the recommended pause between requests (6 s).</summary>
    [Range(1, 600)]
    public int NvdWindowSeconds { get; set; } = 30;

    [Range(0, 600)]
    public double NvdMinSpacingSeconds { get; set; } = 6;

    [Range(1, 10_000)]
    public int CveRequestsPerMinute { get; set; } = 60;

    [Range(1, 10_000)]
    public int EpssRequestsPerMinute { get; set; } = 60;

    [Range(1, 10_000)]
    public int OsvRequestsPerMinute { get; set; } = 600;

    public int NvdPermitLimit => string.IsNullOrWhiteSpace(NvdApiKey) ? 5 : 50;

    [StringLength(200)]
    public string UserAgent { get; set; } = "vuln-manager/1.0 (+https://github.com/DiegoFranciscoG/vuln-manager)";
}
