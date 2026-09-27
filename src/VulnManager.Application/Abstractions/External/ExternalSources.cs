using VulnManager.Domain.Scoring;

namespace VulnManager.Application.Abstractions.External;

public sealed record OsvVulnerabilityRef(string Id, DateTimeOffset? Modified);

public sealed record OsvSeverity(string Type, string Score);

public sealed record OsvRange(string Type, IReadOnlyList<OsvRangeEvent> Events);

public sealed record OsvRangeEvent(string? Introduced, string? Fixed, string? LastAffected, string? Limit);

public sealed record OsvAffected(string? Purl, string? Ecosystem, string? Name, IReadOnlyList<OsvRange> Ranges);

public sealed record OsvVulnerability(
    string Id,
    DateTimeOffset Modified,
    DateTimeOffset? Published,
    DateTimeOffset? Withdrawn,
    IReadOnlyList<string> Aliases,
    string? Summary,
    string? Details,
    IReadOnlyList<OsvSeverity> Severity,
    string? DatabaseSeverity,
    IReadOnlyList<OsvAffected> Affected);

/// <summary>OSV.dev: component → vulnerability matching by purl (GitHub Advisory Database included).</summary>
public interface IOsvClient
{
    /// <summary>One result list per purl, in the same order. Handles OSV pagination tokens.</summary>
    Task<IReadOnlyList<IReadOnlyList<OsvVulnerabilityRef>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken cancellationToken = default);

    Task<OsvVulnerability?> GetVulnerabilityAsync(string id, CancellationToken cancellationToken = default);
}

public sealed record KevCatalogEntry(
    string CveId,
    string VendorProject,
    string Product,
    string VulnerabilityName,
    DateOnly DateAdded,
    DateOnly? DueDate,
    string ShortDescription,
    string RequiredAction,
    bool KnownRansomware,
    bool? ForensicTriage,
    IReadOnlyList<string> Cwes);

public sealed record KevFetchResult(bool NotModified, string? ETag, string? CatalogVersion, IReadOnlyList<KevCatalogEntry> Entries);

/// <summary>CISA KEV JSON feed, fetched with a conditional GET.</summary>
public interface IKevClient
{
    Task<KevFetchResult> FetchAsync(string? etag, CancellationToken cancellationToken = default);
}

public sealed record EpssScore(string CveId, decimal Epss, decimal Percentile, DateOnly Date);

/// <summary>FIRST EPSS API (lookup of up to 100 CVE per call).</summary>
public interface IEpssClient
{
    Task<IReadOnlyList<EpssScore>> GetScoresAsync(IReadOnlyList<string> cveIds, CancellationToken cancellationToken = default);
}

public sealed record PublishedCvss(string Version, string Vector, decimal Score);

public sealed record CveEnrichment(SsvcExploitation? Exploitation, bool? Automatable, TechnicalImpact? TechnicalImpact, PublishedCvss? CnaCvss);

/// <summary>CVE Services API: CISA ADP (Vulnrichment) SSVC decision points and CNA CVSS.</summary>
public interface ICveServicesClient
{
    Task<CveEnrichment?> GetAsync(string cveId, CancellationToken cancellationToken = default);
}

/// <summary>NIST NVD CVE API 2.0, used only to fill missing CVSS scores.</summary>
public interface INvdClient
{
    Task<PublishedCvss?> GetCvssAsync(string cveId, CancellationToken cancellationToken = default);
}

/// <summary>HTTP counters per external source, used to record requests and throttled responses in sync_runs.</summary>
public interface IHttpCallStats
{
    (int Requests, int Throttled) Snapshot(string clientName);
}
