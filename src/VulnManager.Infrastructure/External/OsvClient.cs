using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using VulnManager.Application.Abstractions.External;

namespace VulnManager.Infrastructure.External;

/// <summary>OSV.dev API: POST /v1/querybatch (ids only, paginated) and GET /v1/vulns/{id}.</summary>
public sealed class OsvClient(HttpClient http) : IOsvClient
{
    private const int MaxPages = 20;

    public async Task<IReadOnlyList<IReadOnlyList<OsvVulnerabilityRef>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(purls);
        var results = purls.Select(_ => new List<OsvVulnerabilityRef>()).ToArray();
        var pending = purls.Select((purl, index) => (Index: index, Purl: purl, Token: (string?)null)).ToList();

        for (var page = 0; page < MaxPages && pending.Count > 0; page++)
        {
            var body = new
            {
                queries = pending.Select(p => p.Token is null
                    ? (object)new { package = new { purl = p.Purl } }
                    : new { package = new { purl = p.Purl }, page_token = p.Token }).ToArray(),
            };

            using var response = await http.PostAsJsonAsync("v1/querybatch", body, cancellationToken);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);

            var batchResults = document.RootElement.Arr("results").ToList();
            var next = new List<(int Index, string Purl, string? Token)>();
            for (var i = 0; i < pending.Count && i < batchResults.Count; i++)
            {
                var result = batchResults[i];
                foreach (var vuln in result.Arr("vulns"))
                {
                    if (vuln.Str("id") is { Length: > 0 and <= 50 } id)
                    {
                        results[pending[i].Index].Add(new OsvVulnerabilityRef(id, vuln.Date("modified")));
                    }
                }

                if (result.Str("next_page_token") is { Length: > 0 } token)
                {
                    next.Add((pending[i].Index, pending[i].Purl, token));
                }
            }

            pending = next;
        }

        return results.Select(r => (IReadOnlyList<OsvVulnerabilityRef>)r.DistinctBy(v => v.Id).ToList()).ToList();
    }

    public async Task<OsvVulnerability?> GetVulnerabilityAsync(string id, CancellationToken cancellationToken = default)
    {
        using var response = await http.GetAsync($"v1/vulns/{Uri.EscapeDataString(id)}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(stream, JsonReading.DocumentOptions, cancellationToken);
        return Parse(document.RootElement);
    }

    internal static OsvVulnerability? Parse(JsonElement root)
    {
        if (root.Str("id") is not { Length: > 0 and <= 50 } id || root.Date("modified") is not { } modified)
        {
            return null;
        }

        var severity = root.Arr("severity")
            .Select(s => (Type: s.Str("type"), Score: s.Str("score")))
            .Where(s => s.Type is not null && s.Score is not null)
            .Select(s => new OsvSeverity(s.Type!, s.Score!))
            .ToList();

        var affected = root.Arr("affected").Select(a =>
        {
            var package = a.Obj("package");
            var ranges = a.Arr("ranges").Select(r => new OsvRange(
                r.Str("type") ?? string.Empty,
                r.Arr("events").Select(e => new OsvRangeEvent(e.Str("introduced"), e.Str("fixed"), e.Str("last_affected"), e.Str("limit"))).ToList())).ToList();
            return new OsvAffected(package?.Str("purl"), package?.Str("ecosystem"), package?.Str("name"), ranges);
        }).ToList();

        return new OsvVulnerability(
            id,
            modified,
            root.Date("published"),
            root.Date("withdrawn"),
            root.Arr("aliases").Select(a => a.GetString()).OfType<string>().Where(a => a.Length <= 50).ToList(),
            JsonReading.Clip(root.Str("summary"), 300),
            JsonReading.Clip(root.Str("details"), 20_000),
            severity,
            root.Obj("database_specific")?.Str("severity"),
            affected);
    }
}
