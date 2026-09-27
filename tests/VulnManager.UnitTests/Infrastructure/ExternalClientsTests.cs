using System.Net;
using System.Text.Json;
using VulnManager.Domain.Scoring;
using VulnManager.Infrastructure.External;
using VulnManager.UnitTests.TestSupport;

namespace VulnManager.UnitTests.Infrastructure;

/// <summary>Clients are exercised against real responses captured from each API (tests/fixtures).</summary>
public class ExternalClientsTests
{
    private static HttpClient Client(StubHandler handler, string baseUrl) => new(handler) { BaseAddress = new Uri(baseUrl) };

    [Fact]
    public void OSV_record_is_parsed_with_aliases_vector_and_ranges()
    {
        using var document = JsonDocument.Parse(Fixtures.Read("osv/GHSA-jfh8-c2jp-5v3q.json"));

        var vulnerability = OsvClient.Parse(document.RootElement)!;

        vulnerability.Id.Should().Be("GHSA-jfh8-c2jp-5v3q");
        vulnerability.Aliases.Should().Contain("CVE-2021-44228");
        vulnerability.Severity.Should().ContainSingle(s => s.Type == "CVSS_V3").Which.Score.Should().StartWith("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
        vulnerability.DatabaseSeverity.Should().Be("CRITICAL");
        vulnerability.Affected.Should().Contain(a => a.Purl == "pkg:maven/org.apache.logging.log4j/log4j-core");
    }

    [Fact]
    public async Task OSV_querybatch_maps_results_in_request_order()
    {
        var handler = StubHandler.Json(Fixtures.Read("osv/querybatch-log4j-2.14.1.json"));
        var client = new OsvClient(Client(handler, "https://osv.test/"));

        var results = await client.QueryBatchAsync(["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:npm/left-pad@1.3.0"], TestContext.Current.CancellationToken);

        results[0].Select(r => r.Id).Should().Equal("GHSA-jfh8-c2jp-5v3q", "GHSA-7rjr-3q55-vv33");
        results[1].Should().BeEmpty();
        handler.Requests.Should().ContainSingle().Which.RequestUri!.AbsolutePath.Should().Be("/v1/querybatch");
    }

    [Fact]
    public async Task OSV_unknown_vulnerability_returns_null()
    {
        var client = new OsvClient(Client(StubHandler.Json("{}", HttpStatusCode.NotFound), "https://osv.test/"));

        (await client.GetVulnerabilityAsync("GHSA-0000-0000-0000", TestContext.Current.CancellationToken)).Should().BeNull();
    }

    [Theory]
    [InlineData("cve/CVE-2021-44228.json", SsvcExploitation.Active, true, TechnicalImpact.Total)]
    [InlineData("cve/CVE-2021-45046.json", SsvcExploitation.Active, false, TechnicalImpact.Total)]
    public void CVE_record_exposes_CISA_ADP_SSVC_decision_points(string fixture, SsvcExploitation exploitation, bool automatable, TechnicalImpact impact)
    {
        using var document = JsonDocument.Parse(Fixtures.Read(fixture));

        var enrichment = CveServicesClient.Parse(document.RootElement);

        enrichment.Exploitation.Should().Be(exploitation);
        enrichment.Automatable.Should().Be(automatable);
        enrichment.TechnicalImpact.Should().Be(impact);
    }

    [Fact]
    public async Task NVD_primary_CVSS_v3_1_is_read()
    {
        var client = new NvdClient(Client(StubHandler.Json(Fixtures.Read("nvd/CVE-2021-44228.json")), "https://nvd.test/"));

        var cvss = await client.GetCvssAsync("CVE-2021-44228", TestContext.Current.CancellationToken);

        cvss.Should().NotBeNull();
        cvss!.Version.Should().Be("3.1");
        cvss.Score.Should().Be(10.0m);
        cvss.Vector.Should().Be("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    }

    [Fact]
    public async Task EPSS_scores_are_parsed_from_strings()
    {
        var handler = StubHandler.Json(Fixtures.Read("epss/log4j.json"));
        var client = new EpssClient(Client(handler, "https://epss.test/"));

        var scores = await client.GetScoresAsync(["CVE-2021-44228", "CVE-2021-45046"], TestContext.Current.CancellationToken);

        scores.Should().HaveCount(2);
        scores.Single(s => s.CveId == "CVE-2021-44228").Percentile.Should().Be(1.0m);
        scores.Single(s => s.CveId == "CVE-2021-45046").Date.Should().Be(new DateOnly(2026, 9, 26));
        handler.Requests.Single().RequestUri!.Query.Should().Contain("cve=CVE-2021-44228,CVE-2021-45046");
    }

    [Fact]
    public async Task EPSS_rejects_requests_over_the_documented_2000_character_limit()
    {
        var client = new EpssClient(Client(StubHandler.Json("{}"), "https://epss.test/"));
        var cves = Enumerable.Range(0, 200).Select(i => $"CVE-2024-{i + 10000}").ToList();

        await client.Invoking(c => c.GetScoresAsync(cves, TestContext.Current.CancellationToken)).Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task KEV_feed_is_parsed_and_etag_captured()
    {
        var handler = new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Fixtures.Read("kev/kev-subset.json")) };
            response.Headers.ETag = new System.Net.Http.Headers.EntityTagHeaderValue("\"1abf00-65c534c8b3b50\"");
            return response;
        });
        var client = new KevClient(Client(handler, "https://kev.test/feed.json"));

        var result = await client.FetchAsync(null, TestContext.Current.CancellationToken);

        result.NotModified.Should().BeFalse();
        result.CatalogVersion.Should().Be("2026.09.25");
        result.ETag.Should().Be("\"1abf00-65c534c8b3b50\"");
        var log4shell = result.Entries.Single(e => e.CveId == "CVE-2021-44228");
        log4shell.DateAdded.Should().Be(new DateOnly(2021, 12, 10));
        log4shell.KnownRansomware.Should().BeTrue();
        log4shell.ForensicTriage.Should().BeFalse();
    }

    [Fact]
    public async Task KEV_conditional_get_returns_not_modified()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotModified));
        var client = new KevClient(Client(handler, "https://kev.test/feed.json"));

        var result = await client.FetchAsync("\"1abf00-65c534c8b3b50\"", TestContext.Current.CancellationToken);

        result.NotModified.Should().BeTrue();
        handler.Requests.Single().Headers.IfNoneMatch.Should().ContainSingle().Which.Tag.Should().Be("\"1abf00-65c534c8b3b50\"");
    }
}
