using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VulnManager.Domain.Entities;
using VulnManager.Infrastructure.Persistence.Converters;

namespace VulnManager.Infrastructure.Persistence.Configurations;

internal sealed class AlertConfiguration : IEntityTypeConfiguration<Alert>
{
    public void Configure(EntityTypeBuilder<Alert> builder)
    {
        builder.ToTable("alerts", t => t.HasCheckConstraint("ck_alerts_type", EnumDbNames.CheckSql<AlertType>("type")));
        builder.HasKey(a => a.Id);
        builder.Property(a => a.Message).HasMaxLength(500).IsRequired();
        builder.Property(a => a.DedupKey).HasMaxLength(200).IsRequired();
        builder.HasIndex(a => a.DedupKey).IsUnique();
        builder.HasIndex(a => new { a.ProjectId, a.AcknowledgedAt });
        builder.Property(a => a.AcknowledgedBy).HasMaxLength(100);
        builder.HasOne<Project>().WithMany().HasForeignKey(a => a.ProjectId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne<Finding>().WithMany().HasForeignKey(a => a.FindingId).OnDelete(DeleteBehavior.Restrict);
    }
}

internal sealed class SyncRunConfiguration : IEntityTypeConfiguration<SyncRun>
{
    public void Configure(EntityTypeBuilder<SyncRun> builder)
    {
        builder.ToTable("sync_runs", t =>
        {
            t.HasCheckConstraint("ck_sync_runs_source", EnumDbNames.CheckSql<SyncSource>("source"));
            t.HasCheckConstraint("ck_sync_runs_trigger", EnumDbNames.CheckSql<SyncTrigger>("trigger"));
            t.HasCheckConstraint("ck_sync_runs_status", EnumDbNames.CheckSql<SyncRunStatus>("status"));
        });
        builder.HasKey(s => s.Id);
        builder.HasIndex(s => s.Source).IsUnique().HasFilter("status = 'RUNNING'").HasDatabaseName("ux_sync_runs_single_running");
        builder.HasIndex(s => new { s.Source, s.StartedAt });
        builder.Property(s => s.Watermark).HasMaxLength(100);
        builder.Property(s => s.ErrorMessage).HasMaxLength(1000);
    }
}

internal sealed class AuditLogEntryConfiguration : IEntityTypeConfiguration<AuditLogEntry>
{
    public void Configure(EntityTypeBuilder<AuditLogEntry> builder)
    {
        builder.ToTable("audit_log", t => t.HasCheckConstraint("ck_audit_log_actor_type", EnumDbNames.CheckSql<ActorType>("actor_type")));
        builder.HasKey(a => a.Id);
        builder.Property(a => a.Id).UseIdentityAlwaysColumn();
        builder.Property(a => a.ActorId).HasMaxLength(100).IsRequired();
        builder.Property(a => a.Action).HasMaxLength(50).IsRequired();
        builder.Property(a => a.EntityType).HasMaxLength(50).IsRequired();
        builder.Property(a => a.EntityId).HasMaxLength(100).IsRequired();
        builder.Property(a => a.Details).HasColumnType("jsonb");
        builder.HasIndex(a => a.OccurredAt);
        builder.HasIndex(a => new { a.EntityType, a.EntityId });
    }
}
