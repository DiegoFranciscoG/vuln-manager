using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Sla;
using VulnManager.Domain.Vex;
using VulnManager.IntegrationTests.Infrastructure;

namespace VulnManager.IntegrationTests;

public class VexAndTriageTests(PostgresContainer postgres, ExternalApisStub apis) : IntegrationTestBase(postgres, apis)
{
    [Fact]
    public async Task CycloneDX_vex_marks_not_affected_with_justification_and_survives_new_sboms()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        var content = new ByteArrayContent(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "fixtures", VexDocument)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.cyclonedx+json");

        (await Admin.PostAsync($"/api/projects/{project.Id}/vex", content, Ct)).EnsureSuccessStatusCode();

        var finding = (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-45046");
        finding.Status.Should().Be(FindingStatus.NotAffected);
        var statement = (await ReadAsync<List<VexStatementDto>>(await Admin.GetAsync($"/api/projects/{project.Id}/vex-statements", Ct))).Single();
        statement.JustificationScheme.Should().Be(VexJustificationScheme.CycloneDx);
        statement.Justification.Should().Be("code_not_reachable");
        statement.ImpactStatement.Should().Contain("JndiLookup");

        // A new SBOM with the same component keeps the VEX decision (noise does not come back).
        (await UploadAsync(Admin, project.Id, UpgradedSbom)).EnsureSuccessStatusCode();
        (await UploadAsync(Admin, project.Id, Log4jSbom)).EnsureSuccessStatusCode();
        (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-45046").Status.Should().Be(FindingStatus.NotAffected);
    }

    [Fact]
    public async Task Revoking_a_vex_statement_reopens_the_finding()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        var created = await Admin.PostAsJsonAsync($"/api/projects/{project.Id}/vex-statements", new CreateVexStatementRequest
        {
            VulnerabilityRef = "CVE-2021-44228",
            Status = VexStatus.NotAffected,
            Justification = "component_not_present",
        }, AppJson.Options, Ct);
        created.StatusCode.Should().Be(HttpStatusCode.Created);
        var statement = await ReadAsync<VexStatementDto>(created);
        (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-44228").Status.Should().Be(FindingStatus.NotAffected);

        (await Admin.DeleteAsync($"/api/projects/{project.Id}/vex-statements/{statement.Id}", Ct)).StatusCode.Should().Be(HttpStatusCode.NoContent);

        (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-44228").Status.Should().Be(FindingStatus.New);
    }

    [Fact]
    public async Task Not_affected_without_justification_or_impact_is_rejected()
    {
        var project = await CreateProjectAsync();

        var response = await Admin.PostAsJsonAsync($"/api/projects/{project.Id}/vex-statements", new CreateVexStatementRequest
        {
            VulnerabilityRef = "CVE-2021-44228",
            Status = VexStatus.NotAffected,
        }, AppJson.Options, Ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(Ct)).Should().Contain("justificación");
    }

    [Fact]
    public async Task Analyst_triage_is_recorded_in_history_and_audit()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        using var analyst = await Factory.ClientForAsync(Factory.Analyst);
        var finding = (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-44228");

        var noReason = await analyst.PostAsJsonAsync($"/api/findings/{finding.Id}/status", new ChangeFindingStatusRequest { Status = FindingStatus.Mitigated }, AppJson.Options, Ct);
        noReason.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var accepted = await analyst.PostAsJsonAsync($"/api/findings/{finding.Id}/status", new ChangeFindingStatusRequest
        {
            Status = FindingStatus.Accepted,
            Justification = "Servicio en retiro; se apaga el 2026-10-15.",
            RiskAcceptedUntil = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(20)),
        }, AppJson.Options, Ct);

        accepted.StatusCode.Should().Be(HttpStatusCode.OK);
        var detail = await ReadAsync<FindingDetailDto>(accepted);
        detail.Summary.Status.Should().Be(FindingStatus.Accepted);
        detail.History[^1].Source.Should().Be(StatusChangeSource.User);
        var audit = await Factory.WithDbAsync(db => db.AuditLog.AsNoTracking().Where(a => a.Action == "FINDING_STATUS_CHANGED").ToListAsync(Ct));
        audit.Should().ContainSingle().Which.ActorId.Should().NotContain("@", "the audit trail stores ids, never e-mails");
    }

    [Fact]
    public async Task Activating_a_rule_version_recalculates_every_finding()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        var active = await ReadAsync<PriorityRuleDto>(await Admin.GetAsync("/api/priority-rules/active", Ct));

        var created = await Admin.PostAsJsonAsync("/api/priority-rules", new CreatePriorityRuleRequest
        {
            Name = "SLA por severidad",
            EpssPercentileThreshold = active.EpssPercentileThreshold,
            HighImpactMinCvss = active.HighImpactMinCvss,
            Rules = active.Rules.ToList(),
            SlaPolicy = SlaPolicyType.Severity,
            Activate = true,
        }, AppJson.Options, Ct);

        created.StatusCode.Should().Be(HttpStatusCode.Created);
        var log4shell = (await FindingsAsync(project.Id)).Single(f => f.CveId == "CVE-2021-44228");
        var detail = await ReadAsync<FindingDetailDto>(await Admin.GetAsync($"/api/findings/{log4shell.Id}", Ct));
        detail.SlaExplanation!.Policy.Should().Be(SlaPolicyType.Severity);
        detail.PriorityExplanation!.RuleVersion.Should().Be(2);
    }

    [Fact]
    public async Task Finding_filters_accept_the_enum_names_of_the_json_contract()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        (await Admin.PostAsJsonAsync($"/api/projects/{project.Id}/vex-statements", new CreateVexStatementRequest
        {
            VulnerabilityRef = "CVE-2021-45046",
            Status = VexStatus.NotAffected,
            Justification = "vulnerable_code_not_in_execute_path",
        }, AppJson.Options, Ct)).EnsureSuccessStatusCode();

        var filtered = await Admin.GetAsync($"/api/findings?projectId={project.Id}&status=NOT_AFFECTED&status=FALSE_POSITIVE&sort=SLA_DUE", Ct);

        filtered.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadAsync<PagedResult<FindingListItemDto>>(filtered)).Items.Should().ContainSingle(f => f.CveId == "CVE-2021-45046");
        (await Admin.GetAsync($"/api/findings?projectId={project.Id}&status=4", Ct)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await Admin.GetAsync($"/api/findings?projectId={project.Id}&status=NEW,FIXED", Ct)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Non_exhaustive_rule_sets_are_rejected()
    {
        var response = await Admin.PostAsJsonAsync("/api/priority-rules", new CreatePriorityRuleRequest
        {
            Name = "Incompleta",
            Rules = [new Domain.Prioritization.PriorityRule("R1", new([Domain.Prioritization.ExploitationSignal.Active]), Domain.Prioritization.PriorityLevel.P1, "Solo KEV")],
        }, AppJson.Options, Ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.Content.ReadAsStringAsync(Ct)).Should().Contain("Ninguna regla cubre");
    }
}
