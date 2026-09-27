using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Sync;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;

[assembly: AssemblyFixture(typeof(VulnManager.IntegrationTests.Infrastructure.PostgresContainer))]
[assembly: AssemblyFixture(typeof(VulnManager.IntegrationTests.Infrastructure.ExternalApisStub))]

namespace VulnManager.IntegrationTests.Infrastructure;

/// <summary>Each test gets its own application instance and database.</summary>
public abstract class IntegrationTestBase(PostgresContainer postgres, ExternalApisStub apis) : IAsyncLifetime
{
    public const string Log4jSbom = "sbom/portal-log4j-2.14.1.cdx.json";
    public const string UpgradedSbom = "sbom/portal-log4j-2.17.1.cdx.json";
    public const string VexDocument = "sbom/portal-vex-45046.cdx.json";

    protected ExternalApisStub Apis { get; } = apis;

    protected VulnManagerFactory Factory { get; private set; } = default!;

    protected HttpClient Admin { get; private set; } = default!;

    protected static CancellationToken Ct => TestContext.Current.CancellationToken;

    public virtual async ValueTask InitializeAsync()
    {
        Apis.Server.ResetLogEntries();
        Factory = await VulnManagerFactory.CreateAsync(postgres, Apis, Configure);
        Admin = await Factory.ClientForAsync(Factory.Admin);
    }

    public virtual async ValueTask DisposeAsync()
    {
        Admin.Dispose();
        await Factory.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    protected virtual void Configure(IWebHostBuilder builder)
    {
    }

    protected static async Task<T> ReadAsync<T>(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<T>(AppJson.Options, Ct))!;

    protected async Task<ProjectDto> CreateProjectAsync(string name = "portal-ciudadano-demo", Exposure exposure = Exposure.Public)
    {
        var response = await Admin.PostAsJsonAsync("/api/projects", new ProjectRequest { Name = name, Exposure = exposure }, AppJson.Options, Ct);
        response.EnsureSuccessStatusCode();
        return await ReadAsync<ProjectDto>(response);
    }

    protected async Task<string> CreateApiKeyAsync(Guid projectId)
    {
        var response = await Admin.PostAsJsonAsync($"/api/projects/{projectId}/api-keys", new CreateApiKeyRequest { Name = "pipeline-devsecops", ExpiresInDays = 30 }, AppJson.Options, Ct);
        response.EnsureSuccessStatusCode();
        return (await ReadAsync<ApiKeyCreatedDto>(response)).Secret;
    }

    protected HttpClient ClientWithApiKey(string apiKey)
    {
        var client = Factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
        return client;
    }

    protected static Task<HttpResponseMessage> UploadAsync(HttpClient client, Guid projectId, string fixture, string? sourceRef = null)
    {
        var content = new ByteArrayContent(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "fixtures", fixture)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.cyclonedx+json");
        var url = $"/api/projects/{projectId}/sboms" + (sourceRef is null ? string.Empty : $"?sourceRef={Uri.EscapeDataString(sourceRef)}");
        return client.PostAsync(url, content, Ct);
    }

    protected Task<IReadOnlyList<SyncRunDto>> SyncAsync(SyncSource? source = null) =>
        Factory.Services.GetRequiredService<SyncRunner>().RunAsync(new SyncRequest(source, SyncTrigger.Manual), Ct);

    protected async Task<IReadOnlyList<FindingListItemDto>> FindingsAsync(Guid projectId, HttpClient? client = null)
    {
        var response = await (client ?? Admin).GetAsync($"/api/findings?projectId={projectId}&pageSize=200", Ct);
        response.EnsureSuccessStatusCode();
        return (await ReadAsync<PagedResult<FindingListItemDto>>(response)).Items;
    }

    /// <summary>Creates a project, loads the Log4j SBOM through an ingestion key and runs every sync source.</summary>
    protected async Task<ProjectDto> ProjectWithLog4jFindingsAsync(Exposure exposure = Exposure.Public)
    {
        var project = await CreateProjectAsync(exposure: exposure);
        using var ci = ClientWithApiKey(await CreateApiKeyAsync(project.Id));
        (await UploadAsync(ci, project.Id, Log4jSbom)).EnsureSuccessStatusCode();
        await SyncAsync();
        return project;
    }
}
