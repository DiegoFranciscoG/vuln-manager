using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;
using VulnManager.IntegrationTests.Infrastructure;

namespace VulnManager.IntegrationTests;

public class SbomIngestionTests(PostgresContainer postgres, ExternalApisStub apis) : IntegrationTestBase(postgres, apis)
{
    /// <summary>Acceptance: an SBOM produces verifiable findings (checked against OSV, KEV, CISA SSVC and BOD 26-04).</summary>
    [Fact]
    public async Task Log4j_sbom_produces_verifiable_prioritized_findings()
    {
        var project = await CreateProjectAsync();
        using var ci = ClientWithApiKey(await CreateApiKeyAsync(project.Id));

        var upload = await UploadAsync(ci, project.Id, Log4jSbom, sourceRef: "https://github.com/example/pipeline/actions/runs/1");
        upload.StatusCode.Should().Be(HttpStatusCode.Created);
        var import = await ReadAsync<SbomImportResultDto>(upload);
        import.Import.ComponentCount.Should().Be(2);
        import.Import.SkippedCount.Should().Be(1, "the component without purl cannot be matched");
        import.Import.Source.Should().Be(SbomSource.Api);

        await SyncAsync();
        var findings = await FindingsAsync(project.Id);

        findings.Should().HaveCount(2);
        var log4shell = findings.Single(f => f.CveId == "CVE-2021-44228");
        log4shell.VulnerabilityId.Should().Be("GHSA-jfh8-c2jp-5v3q");
        log4shell.ComponentPurl.Should().Be("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        log4shell.Priority.Should().Be(PriorityLevel.P1);
        log4shell.InKev.Should().BeTrue();
        log4shell.KnownRansomware.Should().BeTrue();
        log4shell.CvssScore.Should().Be(10.0m);
        log4shell.Severity.Should().Be(Severity.Critical);
        log4shell.EpssPercentile.Should().Be(1.0m);
        log4shell.FixAvailable.Should().BeTrue();
        log4shell.SuggestedFixVersion.Should().Be("2.15.0");
        log4shell.ForensicTriageRequired.Should().BeTrue();
        log4shell.SlaDueAt.Should().Be(new DateTimeOffset(2021, 12, 13, 0, 0, 0, TimeSpan.Zero), "BOD 26-04 row 1: 3 days from the KEV date");
        log4shell.Overdue.Should().BeTrue();

        var detail = await ReadAsync<FindingDetailDto>(await Admin.GetAsync($"/api/findings/{log4shell.Id}", Ct));
        detail.PriorityExplanation!.MatchedRule.Should().Be("R1");
        detail.SlaExplanation!.Row.Should().Be(1);
        detail.SlaExplanation.AutomatableSource.Should().Be(SsvcDataSource.CisaAdp);
        detail.SsvcExploitation.Should().Be(SsvcExploitation.Active);
        detail.FixedVersions.Should().Contain("2.15.0");

        var followUp = findings.Single(f => f.CveId == "CVE-2021-45046");
        followUp.Priority.Should().Be(PriorityLevel.P1);
        var followUpDetail = await ReadAsync<FindingDetailDto>(await Admin.GetAsync($"/api/findings/{followUp.Id}", Ct));
        followUpDetail.SlaExplanation!.Row.Should().Be(3, "CISA says Automatable = no, Technical Impact = total");
        followUp.SlaDueAt.Should().Be(new DateTimeOffset(2023, 5, 4, 0, 0, 0, TimeSpan.Zero));
    }

    [Fact]
    public async Task Resending_the_same_sbom_is_idempotent()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        var historyBefore = await Factory.WithDbAsync(db => db.FindingStatusHistory.CountAsync(Ct));

        var again = await UploadAsync(Admin, project.Id, Log4jSbom);

        again.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadAsync<SbomImportResultDto>(again)).Created.Should().BeFalse();
        (await Factory.WithDbAsync(db => db.SbomImports.CountAsync(Ct))).Should().Be(1);
        (await Factory.WithDbAsync(db => db.FindingStatusHistory.CountAsync(Ct))).Should().Be(historyBefore);
        (await FindingsAsync(project.Id)).Should().HaveCount(2);
    }

    [Fact]
    public async Task Upgrading_closes_findings_and_rolling_back_reopens_them()
    {
        var project = await ProjectWithLog4jFindingsAsync();

        (await UploadAsync(Admin, project.Id, UpgradedSbom)).StatusCode.Should().Be(HttpStatusCode.Created);
        await SyncAsync();
        var afterUpgrade = await FindingsAsync(project.Id);
        afterUpgrade.Should().HaveCount(2).And.OnlyContain(f => f.Status == FindingStatus.Fixed);

        var rollback = await UploadAsync(Admin, project.Id, Log4jSbom);
        rollback.StatusCode.Should().Be(HttpStatusCode.OK, "the document was already imported (no duplicate import)");
        (await ReadAsync<SbomImportResultDto>(rollback)).Reconciliation.Reopened.Should().Be(2);

        var detail = await ReadAsync<FindingDetailDto>(await Admin.GetAsync($"/api/findings/{afterUpgrade[0].Id}", Ct));
        detail.Summary.Status.Should().Be(FindingStatus.New);
        detail.History.Select(h => h.To).Should().Equal(FindingStatus.New, FindingStatus.Fixed, FindingStatus.New);
        detail.History.Skip(1).Should().OnlyContain(h => h.Source == StatusChangeSource.SbomImport);
    }

    [Theory]
    [InlineData("not json at all", "application/json", HttpStatusCode.BadRequest)]
    [InlineData("""{"spdxVersion":"SPDX-2.3"}""", "application/json", HttpStatusCode.BadRequest)]
    [InlineData("""{"bomFormat":"CycloneDX","specVersion":"1.6"}""", "text/plain", HttpStatusCode.BadRequest)]
    public async Task Invalid_documents_are_rejected_with_problem_details(string body, string contentType, HttpStatusCode expected)
    {
        var project = await CreateProjectAsync();
        var content = new StringContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);

        var response = await Admin.PostAsync($"/api/projects/{project.Id}/sboms", content, Ct);

        response.StatusCode.Should().BeOneOf(expected, HttpStatusCode.UnsupportedMediaType);
        var text = await response.Content.ReadAsStringAsync(Ct);
        text.Should().NotContainAny("at VulnManager", "StackTrace", "Exception:");
    }

    [Fact]
    public async Task Multipart_upload_from_the_ui_path_is_accepted_and_file_name_sanitized()
    {
        var project = await CreateProjectAsync();
        using var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "fixtures", Log4jSbom)));
        file.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        form.Add(file, "file", "../../etc/bom.cdx.json");

        var response = await Admin.PostAsync($"/api/projects/{project.Id}/sboms", form, Ct);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var result = await ReadAsync<SbomImportResultDto>(response);
        result.Import.FileName.Should().Be("bom.cdx.json");
        result.Import.Source.Should().Be(SbomSource.Upload);
    }

    [Fact]
    public async Task Csv_export_contains_the_findings_and_is_protected()
    {
        var project = await ProjectWithLog4jFindingsAsync();

        var response = await Admin.GetAsync($"/api/findings/export.csv?projectId={project.Id}", Ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType!.MediaType.Should().Be("text/csv");
        var csv = await response.Content.ReadAsStringAsync(Ct);
        csv.Should().Contain("\"CVE-2021-44228\"").And.Contain("\"P1\"");
        csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Should().HaveCount(3);
    }

    [Fact]
    public async Task Changing_the_exposure_recalculates_bod_deadlines()
    {
        var project = await ProjectWithLog4jFindingsAsync(Exposure.Public);
        var before = (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-45046");

        var update = await Admin.PutAsJsonAsync($"/api/projects/{project.Id}", new ProjectRequest { Name = project.Name, Exposure = Exposure.Internal }, AppJson.Options, Ct);
        update.EnsureSuccessStatusCode();

        var after = (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-45046");
        before.SlaDueAt.Should().Be(new DateTimeOffset(2023, 5, 4, 0, 0, 0, TimeSpan.Zero));
        after.SlaDueAt.Should().Be(new DateTimeOffset(2023, 5, 15, 0, 0, 0, TimeSpan.Zero), "row 11 (internal, KEV, not automatable, total) gives 14 days");
    }
}
