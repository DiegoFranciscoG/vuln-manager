using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Testcontainers.PostgreSql;
using VulnManager.Infrastructure.Persistence;

namespace VulnManager.IntegrationTests.Infrastructure;

/// <summary>One PostgreSQL container for the whole test run (Testcontainers), one database per factory.</summary>
public sealed class PostgresContainer : IAsyncLifetime
{
    public const string Image = "postgres:17.11-alpine3.24";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder(Image).Build();

    public async ValueTask InitializeAsync() => await _container.StartAsync();

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();

    public async Task<string> CreateDatabaseAsync()
    {
        var name = "vm_" + Guid.NewGuid().ToString("N");
        await using var connection = new NpgsqlConnection(_container.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE {name}", connection);
        await command.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name }.ConnectionString;
    }
}

/// <summary>Credentials generated per run for the seeded test users (never real data).</summary>
public sealed record TestUser(string Email, string Password);

/// <summary>
/// Boots the real application (migrations, seeding, security pipeline) against its own database and the WireMock stub.
/// The background worker is disabled; tests drive synchronization explicitly through <see cref="Application.Sync.SyncRunner"/>.
/// </summary>
public sealed class VulnManagerFactory(string connectionString, ExternalApisStub apis, Action<IWebHostBuilder>? extra = null) : WebApplicationFactory<Program>
{
    public TestUser Admin { get; } = new("admin@vulnmanager.test", NewPassword());

    public TestUser Analyst { get; } = new("analyst@vulnmanager.test", NewPassword());

    public TestUser Viewer { get; } = new("viewer@vulnmanager.test", NewPassword());

    public string SyncToken { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public static async Task<VulnManagerFactory> CreateAsync(PostgresContainer postgres, ExternalApisStub apis, Action<IWebHostBuilder>? extra = null) =>
        new(await postgres.CreateDatabaseAsync(), apis, extra);

    public async Task<HttpClient> ClientForAsync(TestUser user)
    {
        var client = CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/token", new { email = user.Email, password = user.Password });
        response.EnsureSuccessStatusCode();
        var token = (await response.Content.ReadFromJsonAsync<TokenBody>())!.AccessToken;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public async Task WithDbAsync(Func<VulnManagerDbContext, Task> action)
    {
        await using var scope = Services.CreateAsyncScope();
        await action(scope.ServiceProvider.GetRequiredService<VulnManagerDbContext>());
    }

    public async Task<T> WithDbAsync<T>(Func<VulnManagerDbContext, Task<T>> action)
    {
        await using var scope = Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<VulnManagerDbContext>());
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Default", connectionString);
        builder.UseSetting("Jwt:Secret", Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)));
        builder.UseSetting("Database:ApplyMigrationsOnStartup", "true");
        builder.UseSetting("Seed:DemoData", "false");
        builder.UseSetting("Seed:AdminEmail", Admin.Email);
        builder.UseSetting("Seed:AdminPassword", Admin.Password);
        builder.UseSetting("Seed:AnalystEmail", Analyst.Email);
        builder.UseSetting("Seed:AnalystPassword", Analyst.Password);
        builder.UseSetting("Seed:ViewerEmail", Viewer.Email);
        builder.UseSetting("Seed:ViewerPassword", Viewer.Password);
        builder.UseSetting("Sync:Enabled", "false");
        builder.UseSetting("Security:SecureCookies", "false");
        builder.UseSetting("Sync:OsvBatchSize", "1");
        builder.UseSetting("Sync:TriggerToken", SyncToken);
        builder.UseSetting("ExternalSources:OsvBaseUrl", apis.Url + "/");
        builder.UseSetting("ExternalSources:KevFeedUrl", apis.Url + "/kev.json");
        builder.UseSetting("ExternalSources:EpssBaseUrl", apis.Url + "/");
        builder.UseSetting("ExternalSources:CveServicesBaseUrl", apis.Url + "/");
        builder.UseSetting("ExternalSources:NvdBaseUrl", apis.Url + "/");
        extra?.Invoke(builder);
    }

    private static string NewPassword() => "Vm!" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() + "Z9";

    private sealed record TokenBody(string AccessToken);
}
