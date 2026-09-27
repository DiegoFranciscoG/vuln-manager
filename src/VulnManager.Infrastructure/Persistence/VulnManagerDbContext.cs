using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;
using VulnManager.Domain.Vex;
using VulnManager.Infrastructure.Identity;
using VulnManager.Infrastructure.Persistence.Converters;

namespace VulnManager.Infrastructure.Persistence;

public sealed class VulnManagerDbContext(DbContextOptions<VulnManagerDbContext> options) : IdentityDbContext<AppUser>(options), IDataProtectionKeyContext
{
    /// <summary>ASP.NET Core Data Protection keys: cookies and antiforgery tokens survive restarts (Render free sleeps).</summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    public DbSet<Project> Projects => Set<Project>();

    public DbSet<ProjectApiKey> ProjectApiKeys => Set<ProjectApiKey>();

    public DbSet<SbomImport> SbomImports => Set<SbomImport>();

    public DbSet<SbomComponent> SbomComponents => Set<SbomComponent>();

    public DbSet<Component> Components => Set<Component>();

    public DbSet<ComponentVulnerability> ComponentVulnerabilities => Set<ComponentVulnerability>();

    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();

    public DbSet<KevEntry> KevEntries => Set<KevEntry>();

    public DbSet<Finding> Findings => Set<Finding>();

    public DbSet<FindingStatusChange> FindingStatusHistory => Set<FindingStatusChange>();

    public DbSet<VexStatement> VexStatements => Set<VexStatement>();

    public DbSet<PriorityRuleVersion> PriorityRules => Set<PriorityRuleVersion>();

    public DbSet<Alert> Alerts => Set<Alert>();

    public DbSet<SyncRun> SyncRuns => Set<SyncRun>();

    public DbSet<AuditLogEntry> AuditLog => Set<AuditLogEntry>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        ArgumentNullException.ThrowIfNull(configurationBuilder);
        Map<Exposure>(configurationBuilder);
        Map<DeploymentEnvironment>(configurationBuilder);
        Map<AssetType>(configurationBuilder);
        Map<Severity>(configurationBuilder);
        Map<SsvcExploitation>(configurationBuilder);
        Map<TechnicalImpact>(configurationBuilder);
        Map<CvssSource>(configurationBuilder);
        Map<FindingStatus>(configurationBuilder);
        Map<StatusChangeSource>(configurationBuilder);
        Map<PriorityLevel>(configurationBuilder);
        Map<ImpactSignal>(configurationBuilder);
        Map<SlaPolicyType>(configurationBuilder);
        Map<VexStatus>(configurationBuilder);
        Map<VexJustificationScheme>(configurationBuilder);
        Map<VexSource>(configurationBuilder);
        Map<SbomSource>(configurationBuilder);
        Map<SbomImportStatus>(configurationBuilder);
        Map<AlertType>(configurationBuilder);
        Map<SyncSource>(configurationBuilder);
        Map<SyncTrigger>(configurationBuilder);
        Map<SyncRunStatus>(configurationBuilder);
        Map<ActorType>(configurationBuilder);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(VulnManagerDbContext).Assembly);

        // Identity maps its tables explicitly ("AspNetUsers"); keep every table in snake_case.
        foreach (var entity in builder.Model.GetEntityTypes())
        {
            var table = entity.GetTableName();
            if (table is not null && table.StartsWith("AspNet", StringComparison.Ordinal))
            {
                entity.SetTableName(EnumDbNames.ToUpperSnake(table).ToLowerInvariant());
            }
        }
    }

    private static void Map<TEnum>(ModelConfigurationBuilder builder)
        where TEnum : struct, Enum =>
        builder.Properties<TEnum>().HaveConversion<UpperSnakeEnumConverter<TEnum>>().HaveMaxLength(30);
}
