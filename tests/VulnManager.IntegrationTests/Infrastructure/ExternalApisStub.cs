using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace VulnManager.IntegrationTests.Infrastructure;

/// <summary>
/// WireMock server that plays OSV, KEV, EPSS, CVE Services and NVD with real responses captured from each API.
/// </summary>
public sealed class ExternalApisStub : IDisposable
{
    public const string KevLastModified = "Fri, 25 Sep 2026 18:58:16 GMT";
    public const string KevETag = "\"1abf00-65c534c8b3b50\"";

    public ExternalApisStub()
    {
        Server = WireMockServer.Start();
        StubOsv();
        StubKev();
        StubEpss();
        StubCve();
        StubNvd();
    }

    public WireMockServer Server { get; }

    public string Url => Server.Url!;

    public static string Fixture(string relativePath) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", relativePath));

    public IReadOnlyList<DateTime> RequestTimes(string pathPrefix) =>
        Server.LogEntries
            .Where(e => e.RequestMessage!.Path.StartsWith(pathPrefix, StringComparison.Ordinal))
            .Select(e => e.RequestMessage!.DateTime)
            .OrderBy(t => t)
            .ToList();

    public int Count(string pathPrefix) => RequestTimes(pathPrefix).Count;

    public void Dispose() => Server.Stop();

    private void StubOsv()
    {
        // Tests run with Sync:OsvBatchSize = 1, so each querybatch body carries a single purl.
        Server.Given(Request.Create().WithPath("/v1/querybatch").UsingPost().WithBody(new WildcardMatcher("*log4j-core@2.14.1*")))
            .AtPriority(1)
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody("""
                {"results":[{"vulns":[{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2025-10-22T19:37:02.616807Z"},{"id":"GHSA-7rjr-3q55-vv33","modified":"2025-10-22T19:37:53.742023Z"}]}]}
                """));
        Server.Given(Request.Create().WithPath("/v1/querybatch").UsingPost())
            .AtPriority(10)
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody("""{"results":[{}]}"""));

        foreach (var id in new[] { "GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33" })
        {
            Server.Given(Request.Create().WithPath($"/v1/vulns/{id}").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody(Fixture($"osv/{id}.json")));
        }
    }

    private void StubKev()
    {
        // The real CISA CDN answers 304 to If-Modified-Since.
        Server.Given(Request.Create().WithPath("/kev.json").UsingGet().WithHeader("If-Modified-Since", new WildcardMatcher("*")))
            .AtPriority(1)
            .RespondWith(Response.Create().WithStatusCode(304));
        Server.Given(Request.Create().WithPath("/kev.json").UsingGet())
            .AtPriority(10)
            .RespondWith(Response.Create().WithStatusCode(200)
                .WithHeader("Content-Type", "application/json")
                .WithHeader("ETag", KevETag)
                .WithHeader("Last-Modified", KevLastModified)
                .WithBody(Fixture("kev/kev-subset.json")));
    }

    private void StubEpss() =>
        Server.Given(Request.Create().WithPath("/data/v1/epss").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody(Fixture("epss/log4j.json")));

    private void StubCve()
    {
        foreach (var id in new[] { "CVE-2021-44228", "CVE-2021-45046" })
        {
            Server.Given(Request.Create().WithPath($"/api/cve/{id}").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody(Fixture($"cve/{id}.json")));
        }

        Server.Given(Request.Create().WithPath(new WildcardMatcher("/api/cve/*")).UsingGet())
            .AtPriority(10)
            .RespondWith(Response.Create().WithStatusCode(404));
    }

    private void StubNvd() =>
        Server.Given(Request.Create().WithPath("/rest/json/cves/2.0").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithHeader("Content-Type", "application/json").WithBody(Fixture("nvd/CVE-2021-44228.json")));
}
