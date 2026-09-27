using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VulnManager.Application.Security;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Sla;
using VulnManager.Infrastructure.Identity;

namespace VulnManager.Infrastructure.Persistence;

/// <summary>Demo accounts. Passwords come only from environment variables; a missing password skips that user.</summary>
public sealed class SeedOptions
{
    public const string Section = "Seed";

    public string? AdminEmail { get; set; }

    public string? AdminPassword { get; set; }

    public string? AnalystEmail { get; set; }

    public string? AnalystPassword { get; set; }

    public string? ViewerEmail { get; set; }

    public string? ViewerPassword { get; set; }

    /// <summary>Loads fictitious demo projects with public-package SBOMs when the database has no projects.</summary>
    public bool DemoData { get; set; }
}

public sealed partial class DatabaseInitializer(
    VulnManagerDbContext db,
    RoleManager<IdentityRole> roles,
    UserManager<AppUser> users,
    IOptions<SeedOptions> seed,
    TimeProvider time,
    ILogger<DatabaseInitializer> logger)
{
    public const string DefaultRuleName = "Tabla por defecto (KEV/SSVC + EPSS + CVSS + exposición)";

    public async Task InitializeAsync(bool applyMigrations, CancellationToken cancellationToken = default)
    {
        if (applyMigrations)
        {
            await db.Database.MigrateAsync(cancellationToken);
        }

        foreach (var role in AppRoles.All)
        {
            if (!await roles.RoleExistsAsync(role))
            {
                await roles.CreateAsync(new IdentityRole(role));
            }
        }

        if (!await db.PriorityRules.AnyAsync(cancellationToken))
        {
            var rule = new PriorityRuleVersion(1, DefaultRuleName,
                "Tabla de decisión inicial: KEV/SSVC y EPSS (percentil 0,90) según FIRST, impacto por CVSS >= 7,0 y SLA de la BOD 26-04.",
                PriorityRuleSet.Default, SlaSettings.Default, "system", time.GetUtcNow());
            rule.Activate();
            db.PriorityRules.Add(rule);
            await db.SaveChangesAsync(cancellationToken);
        }

        var options = seed.Value;
        await EnsureUserAsync(options.AdminEmail, options.AdminPassword, AppRoles.Admin);
        await EnsureUserAsync(options.AnalystEmail, options.AnalystPassword, AppRoles.Analyst);
        await EnsureUserAsync(options.ViewerEmail, options.ViewerPassword, AppRoles.Viewer);
    }

    private async Task EnsureUserAsync(string? email, string? password, string role)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            user = new AppUser { UserName = email, Email = email, EmailConfirmed = true, CreatedAt = time.GetUtcNow() };
            var created = await users.CreateAsync(user, password);
            if (!created.Succeeded)
            {
                LogSeedUserFailed(logger, role, string.Join(", ", created.Errors.Select(e => e.Code)));
                return;
            }
        }

        if (!await users.IsInRoleAsync(user, role))
        {
            await users.AddToRoleAsync(user, role);
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Demo {Role} user was not created: {Errors}")]
    private static partial void LogSeedUserFailed(ILogger logger, string role, string errors);
}
