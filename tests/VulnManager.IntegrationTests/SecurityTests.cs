using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Domain.Common;
using VulnManager.Domain.Findings;
using VulnManager.IntegrationTests.Infrastructure;

namespace VulnManager.IntegrationTests;

public class SecurityTests(PostgresContainer postgres, ExternalApisStub apis) : IntegrationTestBase(postgres, apis)
{
    [Theory]
    [InlineData("/api/projects")]
    [InlineData("/api/findings")]
    [InlineData("/api/dashboard")]
    [InlineData("/api/priority-rules/active")]
    public async Task Api_is_deny_by_default(string path)
    {
        using var anonymous = Factory.CreateClient();

        (await anonymous.GetAsync(path, Ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Viewer_can_read_but_cannot_triage_or_administer()
    {
        var project = await ProjectWithLog4jFindingsAsync();
        using var viewer = await Factory.ClientForAsync(Factory.Viewer);
        var finding = (await FindingsAsync(project.Id, viewer))[0];

        var triage = await viewer.PostAsJsonAsync($"/api/findings/{finding.Id}/status",
            new ChangeFindingStatusRequest { Status = FindingStatus.Mitigated, Justification = "Intento de un lector" }, AppJson.Options, Ct);
        var create = await viewer.PostAsJsonAsync("/api/projects", new ProjectRequest { Name = "no-permitido" }, AppJson.Options, Ct);
        var audit = await viewer.GetAsync("/api/audit", Ct);

        triage.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        create.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        audit.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    /// <summary>OWASP API1:2023 (BOLA): an ingestion key only reaches its own project.</summary>
    [Fact]
    public async Task Api_key_is_scoped_to_its_project()
    {
        var mine = await CreateProjectAsync("proyecto-a");
        var other = await CreateProjectAsync("proyecto-b");
        using var ci = ClientWithApiKey(await CreateApiKeyAsync(mine.Id));

        (await UploadAsync(ci, other.Id, Log4jSbom)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await ci.GetAsync($"/api/findings?projectId={other.Id}", Ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        var visible = await ReadAsync<List<ProjectSummaryDto>>(await ci.GetAsync("/api/projects", Ct));
        visible.Should().ContainSingle().Which.Project.Id.Should().Be(mine.Id);
        (await ci.PostAsJsonAsync("/api/projects", new ProjectRequest { Name = "escalada" }, AppJson.Options, Ct)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Revoked_or_forged_api_keys_are_rejected()
    {
        var project = await CreateProjectAsync();
        var key = await CreateApiKeyAsync(project.Id);
        var keys = await ReadAsync<List<ApiKeyDto>>(await Admin.GetAsync($"/api/projects/{project.Id}/api-keys", Ct));
        (await Admin.DeleteAsync($"/api/projects/{project.Id}/api-keys/{keys.Single().Id}", Ct)).EnsureSuccessStatusCode();

        using var revoked = ClientWithApiKey(key);
        using var forged = ClientWithApiKey(key[..^4] + "AAAA");

        (await UploadAsync(revoked, project.Id, Log4jSbom)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await UploadAsync(forged, project.Id, Log4jSbom)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Tampered_or_foreign_jwt_is_rejected()
    {
        using var client = Factory.CreateClient();
        var token = (await ReadAsync<TokenBody>(await client.PostAsJsonAsync("/api/auth/token", new { email = Factory.Admin.Email, password = Factory.Admin.Password }, Ct))).AccessToken;
        var parts = token.Split('.');
        client.DefaultRequestHeaders.Authorization = new("Bearer", $"{parts[0]}.{parts[1]}.invalidsignature");

        (await client.GetAsync("/api/projects", Ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Login_is_rate_limited_and_locks_the_account()
    {
        using var client = Factory.CreateClient();
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 12; i++)
        {
            var response = await client.PostAsJsonAsync("/api/auth/token", new { email = Factory.Viewer.Email, password = "WrongPassword!1" }, Ct);
            statuses.Add(response.StatusCode);
        }

        statuses.Should().Contain(HttpStatusCode.TooManyRequests);
        statuses.TakeWhile(s => s != HttpStatusCode.TooManyRequests).Should().OnlyContain(s => s == HttpStatusCode.Unauthorized);
        var locked = await Factory.WithDbAsync(db => db.Users.AsNoTracking().SingleAsync(u => u.Email == Factory.Viewer.Email, Ct));
        locked.LockoutEnd.Should().NotBeNull("Identity locks the account after 5 failures");
    }

    [Fact]
    public async Task Login_page_views_are_not_throttled_and_blocked_browsers_get_a_page_instead_of_a_redirect_loop()
    {
        using var browser = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        for (var i = 0; i < 15; i++)
        {
            (await browser.GetAsync("/login", Ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        }

        HttpResponseMessage? last = null;
        for (var i = 0; i < 12; i++)
        {
            last = await browser.PostAsync("/login", new FormUrlEncodedContent([]), Ct);
        }

        last!.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        last.Headers.Location.Should().BeNull();
        last.Headers.RetryAfter.Should().NotBeNull();
        (await last.Content.ReadAsStringAsync(Ct)).Should().Contain("Demasiados intentos");
    }

    [Fact]
    public async Task Responses_carry_security_headers_and_no_server_banner()
    {
        var response = await Admin.GetAsync("/api/projects", Ct);

        response.Headers.GetValues("X-Content-Type-Options").Should().Equal("nosniff");
        response.Headers.GetValues("X-Frame-Options").Should().Equal("DENY");
        response.Headers.GetValues("Content-Security-Policy").Single().Should().Contain("default-src 'self'").And.Contain("frame-ancestors 'none'");
        response.Headers.GetValues("Referrer-Policy").Should().Equal("no-referrer");
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
        response.Headers.Contains("Server").Should().BeFalse();
    }

    [Fact]
    public async Task Health_and_openapi_are_public_and_document_both_auth_schemes()
    {
        using var anonymous = Factory.CreateClient();

        (await anonymous.GetAsync("/health/live", Ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await anonymous.GetAsync("/health/ready", Ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        var openApi = await anonymous.GetStringAsync("/openapi/v1.json", Ct);
        openApi.Should().Contain("\"X-Api-Key\"").And.Contain("\"bearer\"").And.Contain("/api/projects/{id}/sboms");
    }

    [Fact]
    public async Task Audit_trail_is_append_only_in_the_database()
    {
        await CreateProjectAsync();

        var act = () => Factory.WithDbAsync(db => db.Database.ExecuteSqlRawAsync("UPDATE audit_log SET action = 'TAMPERED'", Ct));

        (await act.Should().ThrowAsync<PostgresException>()).Which.MessageText.Should().Contain("append-only");
    }

    [Fact]
    public async Task Duplicate_project_names_conflict_case_insensitively()
    {
        await CreateProjectAsync("Portal-Demo", Exposure.Public);

        var duplicate = await Admin.PostAsJsonAsync("/api/projects", new ProjectRequest { Name = "portal-demo" }, AppJson.Options, Ct);

        duplicate.StatusCode.Should().Be(HttpStatusCode.Conflict);
    }

    private sealed record TokenBody(string AccessToken);
}
