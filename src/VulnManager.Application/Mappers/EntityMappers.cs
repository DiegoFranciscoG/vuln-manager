using VulnManager.Application.Dtos;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Mappers;

public static class EntityMappers
{
    public static ProjectDto ToDto(this Project project)
    {
        ArgumentNullException.ThrowIfNull(project);
        return new ProjectDto(
            project.Id,
            project.Name,
            project.Description,
            project.RepositoryUrl,
            project.Exposure,
            project.Environment,
            project.AssetType,
            project.CurrentSbomImportId,
            project.CreatedAt,
            project.UpdatedAt,
            project.ArchivedAt is not null);
    }

    public static ApiKeyDto ToDto(this ProjectApiKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new ApiKeyDto(key.Id, key.ProjectId, key.Name, key.KeyPrefix, key.CreatedAt, key.ExpiresAt, key.LastUsedAt, key.RevokedAt);
    }

    public static SbomImportDto ToDto(this SbomImport import)
    {
        ArgumentNullException.ThrowIfNull(import);
        return new SbomImportDto(
            import.Id,
            import.ProjectId,
            import.SpecVersion,
            import.BomSerialNumber,
            import.Source,
            import.SourceRef,
            import.FileName,
            import.Sha256,
            import.SizeBytes,
            import.ComponentCount,
            import.SkippedCount,
            import.Status,
            import.ErrorMessage,
            import.ImportedAt,
            import.ProcessedAt);
    }

    public static VexStatementDto ToDto(this VexStatement statement)
    {
        ArgumentNullException.ThrowIfNull(statement);
        return new VexStatementDto(
            statement.Id,
            statement.ProjectId,
            statement.VulnerabilityRef,
            statement.ComponentPurl,
            statement.Status,
            statement.JustificationScheme,
            statement.Justification,
            statement.ImpactStatement,
            statement.ActionStatement,
            statement.CdxState,
            statement.Source,
            statement.Author,
            statement.CreatedAt,
            statement.RevokedAt);
    }

    public static PriorityRuleDto ToDto(this PriorityRuleVersion rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return new PriorityRuleDto(
            rule.Id,
            rule.Version,
            rule.Name,
            rule.Notes,
            rule.IsActive,
            rule.EpssPercentileThreshold,
            rule.HighImpactMinCvss,
            rule.UnknownSeverityAs,
            rule.SsvcActiveCountsAsExploited,
            rule.Rules,
            rule.SlaPolicy,
            rule.SlaSeverityDays,
            rule.FixOnUpgradeDays,
            rule.CreatedBy,
            rule.CreatedAt);
    }

    public static SyncRunDto ToDto(this SyncRun run)
    {
        ArgumentNullException.ThrowIfNull(run);
        return new SyncRunDto(
            run.Id,
            run.Source,
            run.Trigger,
            run.Status,
            run.StartedAt,
            run.FinishedAt,
            run.ItemsRequested,
            run.ItemsUpdated,
            run.HttpRequests,
            run.HttpThrottled,
            run.Watermark,
            run.ErrorMessage);
    }
}
