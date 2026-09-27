using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Sla;
using VulnManager.Domain.Vex;
using VulnManager.Infrastructure.Persistence.Converters;

namespace VulnManager.Infrastructure.Persistence.Configurations;

internal sealed class FindingConfiguration : IEntityTypeConfiguration<Finding>
{
    public void Configure(EntityTypeBuilder<Finding> builder)
    {
        builder.ToTable("findings", t =>
        {
            t.HasCheckConstraint("ck_findings_status", EnumDbNames.CheckSql<FindingStatus>("status"));
            t.HasCheckConstraint("ck_findings_priority_level", EnumDbNames.CheckSql<PriorityLevel>("priority_level"));
            t.HasCheckConstraint("ck_findings_sla_policy", EnumDbNames.CheckSql<SlaPolicyType>("sla_policy"));
            t.HasCheckConstraint("ck_findings_accepted_until", "status <> 'ACCEPTED' OR risk_accepted_until IS NOT NULL");
            t.HasCheckConstraint("ck_findings_not_affected_vex", "status <> 'NOT_AFFECTED' OR vex_statement_id IS NOT NULL");
            t.HasCheckConstraint("ck_findings_sla_row", "sla_row IS NULL OR (sla_row BETWEEN 1 AND 16)");
        });
        builder.HasKey(f => f.Id);
        builder.HasIndex(f => new { f.ProjectId, f.ComponentId, f.VulnerabilityId }).IsUnique();
        builder.HasIndex(f => new { f.ProjectId, f.Status, f.PriorityLevel });
        builder.HasIndex(f => f.SlaDueAt).HasFilter("status = 'NEW'");
        builder.HasIndex(f => f.VulnerabilityId);
        builder.Property(f => f.StatusReason).HasMaxLength(FindingTransitions.MaxJustificationLength);
        builder.Property(f => f.PriorityExplanation).HasColumnType("jsonb").IsRequired();
        builder.Property(f => f.SlaExplanation).HasColumnType("jsonb").IsRequired();
        builder.Property(f => f.Version).IsRowVersion();
        builder.HasOne<Project>().WithMany().HasForeignKey(f => f.ProjectId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Component>().WithMany().HasForeignKey(f => f.ComponentId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Vulnerability>().WithMany().HasForeignKey(f => f.VulnerabilityId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<SbomImport>().WithMany().HasForeignKey(f => f.DetectedInImportId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<PriorityRuleVersion>().WithMany().HasForeignKey(f => f.PriorityRuleId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<VexStatement>().WithMany().HasForeignKey(f => f.VexStatementId).OnDelete(DeleteBehavior.Restrict);
        builder.HasMany(f => f.History).WithOne().HasForeignKey(h => h.FindingId).OnDelete(DeleteBehavior.Restrict);
        builder.Navigation(f => f.History).UsePropertyAccessMode(PropertyAccessMode.Field);
    }
}

internal sealed class FindingStatusChangeConfiguration : IEntityTypeConfiguration<FindingStatusChange>
{
    public void Configure(EntityTypeBuilder<FindingStatusChange> builder)
    {
        builder.ToTable("finding_status_history", t =>
        {
            t.HasCheckConstraint("ck_finding_status_history_from", EnumDbNames.CheckSql<FindingStatus>("from_status", nullable: true));
            t.HasCheckConstraint("ck_finding_status_history_to", EnumDbNames.CheckSql<FindingStatus>("to_status"));
            t.HasCheckConstraint("ck_finding_status_history_source", EnumDbNames.CheckSql<StatusChangeSource>("change_source"));
        });
        builder.HasKey(h => h.Id);
        builder.Property(h => h.Id).UseIdentityAlwaysColumn();
        builder.Property(h => h.Justification).HasMaxLength(FindingTransitions.MaxJustificationLength);
        builder.Property(h => h.ChangedBy).HasMaxLength(100).IsRequired();
        builder.HasIndex(h => new { h.FindingId, h.ChangedAt });
    }
}

internal sealed class VexStatementConfiguration : IEntityTypeConfiguration<VexStatement>
{
    public void Configure(EntityTypeBuilder<VexStatement> builder)
    {
        var cisa = string.Join(", ", VexJustifications.Cisa.Select(j => $"'{j}'"));
        var cdx = string.Join(", ", VexJustifications.CycloneDx.Select(j => $"'{j}'"));
        builder.ToTable("vex_statements", t =>
        {
            t.HasCheckConstraint("ck_vex_statements_status", EnumDbNames.CheckSql<VexStatus>("status"));
            t.HasCheckConstraint("ck_vex_statements_source", EnumDbNames.CheckSql<VexSource>("source"));
            t.HasCheckConstraint("ck_vex_statements_justification",
                $"justification IS NULL OR (justification_scheme = 'CISA' AND justification IN ({cisa})) OR (justification_scheme = 'CYCLONE_DX' AND justification IN ({cdx}))");
            t.HasCheckConstraint("ck_vex_statements_not_affected", "status <> 'NOT_AFFECTED' OR justification IS NOT NULL OR impact_statement IS NOT NULL");
            t.HasCheckConstraint("ck_vex_statements_affected", "status <> 'AFFECTED' OR action_statement IS NOT NULL");
        });
        builder.HasKey(v => v.Id);
        builder.Property(v => v.VulnerabilityRef).HasMaxLength(50).IsRequired();
        builder.Property(v => v.ComponentPurl).HasMaxLength(1000);
        builder.Property(v => v.Justification).HasMaxLength(60);
        builder.Property(v => v.ImpactStatement).HasMaxLength(VexStatementRules.MaxStatementLength);
        builder.Property(v => v.ActionStatement).HasMaxLength(VexStatementRules.MaxStatementLength);
        builder.Property(v => v.CdxState).HasMaxLength(30);
        builder.Property(v => v.Author).HasMaxLength(100).IsRequired();
        builder.Property(v => v.RevokedBy).HasMaxLength(100);
        builder.HasIndex(v => new { v.ProjectId, v.VulnerabilityRef }).HasFilter("revoked_at IS NULL");
        builder.HasOne<Project>().WithMany().HasForeignKey(v => v.ProjectId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<SbomImport>().WithMany().HasForeignKey(v => v.SourceImportId).OnDelete(DeleteBehavior.Restrict);
    }
}

internal sealed class PriorityRuleVersionConfiguration : IEntityTypeConfiguration<PriorityRuleVersion>
{
    public void Configure(EntityTypeBuilder<PriorityRuleVersion> builder)
    {
        builder.ToTable("priority_rules", t =>
        {
            t.HasCheckConstraint("ck_priority_rules_epss_threshold", "epss_percentile_threshold > 0 AND epss_percentile_threshold <= 1");
            t.HasCheckConstraint("ck_priority_rules_high_impact", "high_impact_min_cvss >= 0 AND high_impact_min_cvss <= 10");
            t.HasCheckConstraint("ck_priority_rules_unknown", EnumDbNames.CheckSql<ImpactSignal>("unknown_severity_as"));
            t.HasCheckConstraint("ck_priority_rules_sla_policy", EnumDbNames.CheckSql<SlaPolicyType>("sla_policy"));
        });
        builder.HasKey(r => r.Id);
        builder.HasIndex(r => r.Version).IsUnique();
        builder.HasIndex(r => r.IsActive).IsUnique().HasFilter("is_active");
        builder.Property(r => r.Name).HasMaxLength(100).IsRequired();
        builder.Property(r => r.Notes).HasMaxLength(500);
        builder.Property(r => r.EpssPercentileThreshold).HasPrecision(4, 3);
        builder.Property(r => r.HighImpactMinCvss).HasPrecision(3, 1);
        builder.Property(r => r.Rules).HasJsonConversion().IsRequired();
        builder.Property(r => r.SlaSeverityDays).HasJsonConversion().IsRequired();
        builder.Property(r => r.CreatedBy).HasMaxLength(100).IsRequired();
    }
}
