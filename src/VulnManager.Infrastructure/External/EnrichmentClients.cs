using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using VulnManager.Application.Abstractions.External;
using VulnManager.Domain.Scoring;

namespace VulnManager.Infrastructure.External;

/// <summary>CISA KEV JSON feed with conditional GET (If-None-Match).</summary>
public sealed class KevClient(HttpClient http) : IKevClient
{
    public async Task<KevFetchResult> FetchAsync(string? etag, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, string.Empty);
        if (!string.IsNullOrWhiteSpace(etag) && EntityTagHeaderValue.TryParse(etag, out var tag))
        {
            request.Headers.IfNoneMatch.Add(tag);
        }

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            return new KevFetchResult(true, etag, null, []);
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);
        var root = document.RootElement;

        var entries = new List<KevCatalogEntry>();
        foreach (var item in root.Arr("vulnerabilities"))
        {
            if (item.Str("cveID") is not { Length: > 0 and <= 20 } cve || item.DateOnlyValue("dateAdded") is not { } added)
            {
                continue;
            }

            entries.Add(new KevCatalogEntry(
                cve.ToUpperInvariant(),
                item.Str("vendorProject") ?? string.Empty,
                item.Str("product") ?? string.Empty,
                item.Str("vulnerabilityName") ?? string.Empty,
                added,
                item.DateOnlyValue("dueDate"),
                item.Str("shortDescription") ?? string.Empty,
                item.Str("requiredAction") ?? string.Empty,
                string.Equals(item.Str("knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase),
                item.Str("forensicTriage") switch
                {
                    { } v when v.Equals("Yes", StringComparison.OrdinalIgnoreCase) => true,
                    { } v when v.Equals("No", StringComparison.OrdinalIgnoreCase) => false,
                    _ => null,
                },
                item.Arr("cwes").Select(c => c.GetString()).OfType<string>().ToList()));
        }

        return new KevFetchResult(false, response.Headers.ETag?.ToString(), JsonReading.Clip(root.Str("catalogVersion"), 20), entries);
    }
}

/// <summary>FIRST EPSS API: GET /data/v1/epss?cve=a,b,c (up to 100 per call).</summary>
public sealed class EpssClient(HttpClient http) : IEpssClient
{
    public async Task<IReadOnlyList<EpssScore>> GetScoresAsync(IReadOnlyList<string> cveIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(cveIds);
        if (cveIds.Count == 0)
        {
            return [];
        }

        var list = string.Join(',', cveIds.Select(Uri.EscapeDataString));
        if (list.Length > 2000)
        {
            throw new ArgumentException("The EPSS API accepts at most 2000 characters in the cve parameter.", nameof(cveIds));
        }

        using var response = await http.GetAsync($"data/v1/epss?cve={list}&limit={cveIds.Count}", cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);

        var scores = new List<EpssScore>();
        foreach (var item in document.RootElement.Arr("data"))
        {
            if (item.Str("cve") is { } cve && item.Dec("epss") is { } epss && item.Dec("percentile") is { } percentile && item.DateOnlyValue("date") is { } date
                && epss is >= 0 and <= 1 && percentile is >= 0 and <= 1)
            {
                scores.Add(new EpssScore(cve.ToUpperInvariant(), decimal.Round(epss, 5), decimal.Round(percentile, 5), date));
            }
        }

        return scores;
    }
}

/// <summary>CVE Services: GET /api/cve/{id}; reads the CISA ADP SSVC metrics and the CNA CVSS.</summary>
public sealed class CveServicesClient(HttpClient http) : ICveServicesClient
{
    public async Task<CveEnrichment?> GetAsync(string cveId, CancellationToken cancellationToken = default)
    {
        using var response = await http.GetAsync($"api/cve/{Uri.EscapeDataString(cveId)}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);
        return Parse(document.RootElement);
    }

    internal static CveEnrichment Parse(JsonElement root)
    {
        var containers = root.Obj("containers");
        SsvcExploitation? exploitation = null;
        bool? automatable = null;
        TechnicalImpact? impact = null;
        PublishedCvss? cvss = containers?.Obj("cna") is { } cna ? ReadCvss(cna) : null;

        foreach (var adp in containers?.Arr("adp") ?? [])
        {
            if (!string.Equals(adp.Obj("providerMetadata")?.Str("shortName"), "CISA-ADP", StringComparison.Ordinal))
            {
                continue;
            }

            cvss ??= ReadCvss(adp);
            foreach (var metric in adp.Arr("metrics"))
            {
                var other = metric.Obj("other");
                if (other?.Str("type") != "ssvc" || other.Value.Obj("content") is not { } content)
                {
                    continue;
                }

                foreach (var option in content.Arr("options"))
                {
                    exploitation ??= option.Str("Exploitation")?.ToLowerInvariant() switch
                    {
                        "none" => SsvcExploitation.None,
                        "poc" or "public poc" => SsvcExploitation.Poc,
                        "active" => SsvcExploitation.Active,
                        _ => null,
                    };
                    automatable ??= option.Str("Automatable")?.ToLowerInvariant() switch
                    {
                        "yes" => true,
                        "no" => false,
                        _ => null,
                    };
                    impact ??= option.Str("Technical Impact")?.ToLowerInvariant() switch
                    {
                        "total" => TechnicalImpact.Total,
                        "partial" => TechnicalImpact.Partial,
                        _ => null,
                    };
                }
            }
        }

        return new CveEnrichment(exploitation, automatable, impact, cvss);
    }

    private static PublishedCvss? ReadCvss(JsonElement container)
    {
        foreach (var (key, version) in new[] { ("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0") })
        {
            foreach (var metric in container.Arr("metrics"))
            {
                if (metric.Obj(key) is { } data && data.Str("vectorString") is { Length: <= 200 } vector && data.Dec("baseScore") is { } score and >= 0 and <= 10)
                {
                    return new PublishedCvss(version, vector, score);
                }
            }
        }

        return null;
    }
}

/// <summary>NVD CVE API 2.0: GET /rest/json/cves/2.0?cveId=... (primary CVSS v4.0, then v3.1, then v3.0).</summary>
public sealed class NvdClient(HttpClient http) : INvdClient
{
    public async Task<PublishedCvss?> GetCvssAsync(string cveId, CancellationToken cancellationToken = default)
    {
        using var response = await http.GetAsync($"rest/json/cves/2.0?cveId={Uri.EscapeDataString(cveId)}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);
        var cve = document.RootElement.Arr("vulnerabilities").Select(v => v.Obj("cve")).FirstOrDefault(c => c is not null);
        var metrics = cve?.Obj("metrics");
        if (metrics is null)
        {
            return null;
        }

        foreach (var (key, version) in new[] { ("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0") })
        {
            var candidates = metrics.Value.Arr(key).ToList();
            var chosen = candidates.FirstOrDefault(m => m.Str("type") == "Primary");
            if (chosen.ValueKind == JsonValueKind.Undefined && candidates.Count > 0)
            {
                chosen = candidates[0];
            }

            if (chosen.ValueKind == JsonValueKind.Object && chosen.Obj("cvssData") is { } data
                && data.Str("vectorString") is { Length: <= 200 } vector && data.Dec("baseScore") is { } score and >= 0 and <= 10)
            {
                return new PublishedCvss(version, vector, score);
            }
        }

        return null;
    }
}
