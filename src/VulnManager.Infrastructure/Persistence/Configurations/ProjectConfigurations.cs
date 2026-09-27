using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Infrastructure.Persistence.Converters;

namespace VulnManager.Infrastructure.Persistence.Configurations;

internal sealed class ProjectConfiguration : IEntityTypeConfiguration<Project>
{
    public void Configure(EntityTypeBuilder<Project> builder)
    {
        builder.ToTable("projects", t =>
        {
            t.HasCheckConstraint("ck_projects_exposure", EnumDbNames.CheckSql<Exposure>("exposure"));
            t.HasCheckConstraint("ck_projects_environment", EnumDbNames.CheckSql<DeploymentEnvironment>("environment"));
            t.HasCheckConstraint("ck_projects_asset_type", EnumDbNames.CheckSql<AssetType>("asset_type"));
            t.HasCheckConstraint("ck_projects_repository_url", "repository_url IS NULL OR repository_url LIKE 'https://%'");
        });
        builder.HasKey(p => p.Id);
        builder.Property(p => p.Name).HasMaxLength(100).IsRequired();
        builder.Property(p => p.Description).HasMaxLength(500);
        builder.Property(p => p.RepositoryUrl).HasMaxLength(300);
        builder.Property(p => p.Version).IsRowVersion();
        builder.HasOne<SbomImport>().WithMany().HasForeignKey(p => p.CurrentSbomImportId).OnDelete(DeleteBehavior.Restrict);
    }
}

internal sealed class ProjectApiKeyConfiguration : IEntityTypeConfiguration<ProjectApiKey>
{
    public void Configure(EntityTypeBuilder<ProjectApiKey> builder)
    {
        builder.ToTable("project_api_keys", t => t.HasCheckConstraint("ck_project_api_keys_hash_length", "octet_length(key_hash) = 32"));
        builder.HasKey(k => k.Id);
        builder.Property(k => k.Name).HasMaxLength(100).IsRequired();
        builder.Property(k => k.KeyPrefix).HasMaxLength(ProjectApiKey.PrefixLength).IsFixedLength().IsRequired();
        builder.HasIndex(k => k.KeyPrefix).IsUnique();
        builder.Property(k => k.KeyHash).IsRequired();
        builder.Property(k => k.CreatedBy).HasMaxLength(100).IsRequired();
        builder.HasOne<Project>().WithMany().HasForeignKey(k => k.ProjectId).OnDelete(DeleteBehavior.Cascade);
    }
}

internal sealed class SbomImportConfiguration : IEntityTypeConfiguration<SbomImport>
{
    public void Configure(EntityTypeBuilder<SbomImport> builder)
    {
        builder.ToTable("sbom_imports", t =>
        {
            t.HasCheckConstraint("ck_sbom_imports_format", $"format IN ('{SbomImport.CycloneDxJson}')");
            t.HasCheckConstraint("ck_sbom_imports_source", EnumDbNames.CheckSql<SbomSource>("source"));
            t.HasCheckConstraint("ck_sbom_imports_status", EnumDbNames.CheckSql<SbomImportStatus>("status"));
            t.HasCheckConstraint("ck_sbom_imports_size", $"size_bytes > 0 AND size_bytes <= {SbomImport.MaxSizeBytes}");
            t.HasCheckConstraint("ck_sbom_imports_sha256", "sha256 ~ '^[0-9a-f]{64}$'");
        });
        builder.HasKey(s => s.Id);
        builder.Property(s => s.Format).HasMaxLength(20).IsRequired();
        builder.Property(s => s.SpecVersion).HasMaxLength(5).IsRequired();
        builder.Property(s => s.BomSerialNumber).HasMaxLength(100);
        builder.Property(s => s.SourceRef).HasMaxLength(300);
        builder.Property(s => s.FileName).HasMaxLength(255);
        builder.Property(s => s.Sha256).HasMaxLength(64).IsFixedLength().IsRequired();
        builder.Property(s => s.ErrorMessage).HasMaxLength(500);
        builder.Property(s => s.ImportedBy).HasMaxLength(100).IsRequired();
        builder.HasIndex(s => new { s.ProjectId, s.Sha256 }).IsUnique();
        builder.HasOne<Project>().WithMany().HasForeignKey(s => s.ProjectId).OnDelete(DeleteBehavior.Restrict);
        builder.HasMany(s => s.Components).WithOne().HasForeignKey(c => c.SbomImportId).OnDelete(DeleteBehavior.Cascade);
        builder.Navigation(s => s.Components).UsePropertyAccessMode(PropertyAccessMode.Field);
    }
}

internal sealed class SbomComponentConfiguration : IEntityTypeConfiguration<SbomComponent>
{
    public void Configure(EntityTypeBuilder<SbomComponent> builder)
    {
        builder.ToTable("sbom_components", t =>
            t.HasCheckConstraint("ck_sbom_components_scope", "scope IS NULL OR scope IN ('required', 'optional', 'excluded')"));
        builder.HasKey(c => new { c.SbomImportId, c.ComponentId });
        builder.Property(c => c.BomRef).HasMaxLength(1000);
        builder.Property(c => c.Scope).HasMaxLength(20);
        builder.HasOne<Component>().WithMany().HasForeignKey(c => c.ComponentId).OnDelete(DeleteBehavior.Restrict);
    }
}
