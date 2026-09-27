using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Security;
using VulnManager.Application.Services;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Vex;
using VulnManager.Infrastructure.Persistence;

namespace VulnManager.Web.Seeding;

/// <summary>
/// Fictitious demo projects with SBOMs of real public packages that have well-known vulnerabilities. No personal data.
/// Runs only when Seed:DemoData is true and the database has no projects; OSV matching happens in the background.
/// </summary>
public sealed partial class DemoDataSeeder(
    ProjectService projects,
    SbomImportService imports,
    VexService vex,
    IWebHostEnvironment environment,
    ILogger<DemoDataSeeder> logger)
{
    private static readonly Actor SeedActor = new(ActorType.System, "seed", [AppRoles.Admin]);

    private static readonly (string Name, string Description, Exposure Exposure, string File)[] Demos =
    [
        ("portal-ciudadano-demo", "Portal web público de trámites (Java/Spring). Ficticio.", Exposure.Public, "portal-ciudadano-demo.cdx.json"),
        ("api-pagos-demo", "API de pagos expuesta a Internet (.NET + Node). Ficticio.", Exposure.Public, "api-pagos-demo.cdx.json"),
        ("backoffice-rrhh-demo", "Backoffice interno de talento humano (Node + Python). Ficticio.", Exposure.Internal, "backoffice-rrhh-demo.cdx.json"),
    ];

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        if ((await projects.ListAsync(SeedActor, includeArchived: true, cancellationToken)).Count > 0)
        {
            return;
        }

        foreach (var demo in Demos)
        {
            var project = await projects.CreateAsync(SeedActor, new ProjectRequest
            {
                Name = demo.Name,
                Description = demo.Description,
                Exposure = demo.Exposure,
                Environment = DeploymentEnvironment.Production,
                AssetType = AssetType.Application,
            }, cancellationToken);

            var content = await File.ReadAllBytesAsync(Path.Combine(environment.ContentRootPath, "SeedData", demo.File), cancellationToken);
            await imports.ImportAsync(SeedActor, project.Id, content, demo.File, SbomSource.Upload, "seed", cancellationToken);

            if (demo.Name == "portal-ciudadano-demo")
            {
                await vex.CreateAsync(SeedActor, project.Id, new CreateVexStatementRequest
                {
                    VulnerabilityRef = "CVE-2021-45046",
                    ComponentPurl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    Status = VexStatus.NotAffected,
                    Justification = "vulnerable_code_not_in_execute_path",
                    ImpactStatement = "La aplicación no usa Thread Context Map lookups en sus patrones de log (ejemplo de VEX).",
                }, cancellationToken);
            }
        }

        LogSeeded(logger, Demos.Length);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Demo data seeded: {Count} fictitious projects; OSV matching runs in the background")]
    private static partial void LogSeeded(ILogger logger, int count);
}

public static class DatabaseStartup
{
    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);
        await using var scope = app.Services.CreateAsyncScope();
        var applyMigrations = app.Configuration.GetValue("Database:ApplyMigrationsOnStartup", false);
        await scope.ServiceProvider.GetRequiredService<DatabaseInitializer>().InitializeAsync(applyMigrations);

        if (app.Configuration.GetValue("Seed:DemoData", false))
        {
            await scope.ServiceProvider.GetRequiredService<DemoDataSeeder>().SeedAsync();
        }
    }
}
