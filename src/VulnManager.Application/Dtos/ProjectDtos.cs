using System.ComponentModel.DataAnnotations;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Dtos;

public sealed record ProjectDto(
    Guid Id,
    string Name,
    string? Description,
    string? RepositoryUrl,
    Exposure Exposure,
    DeploymentEnvironment Environment,
    AssetType AssetType,
    Guid? CurrentSbomImportId,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    bool Archived);

public sealed class ProjectRequest
{
    [Required(ErrorMessage = "El nombre es obligatorio.")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "El nombre debe tener entre 2 y 100 caracteres.")]
    [RegularExpression(@"^[\p{L}\p{N} ._\-]+$", ErrorMessage = "El nombre solo admite letras, números, espacios, punto, guion y guion bajo.")]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    [StringLength(300)]
    [RegularExpression(@"^https://\S+$", ErrorMessage = "La URL del repositorio debe usar https.")]
    public string? RepositoryUrl { get; set; }

    [EnumDataType(typeof(Exposure))]
    public Exposure Exposure { get; set; } = Exposure.Internal;

    [EnumDataType(typeof(DeploymentEnvironment))]
    public DeploymentEnvironment Environment { get; set; } = DeploymentEnvironment.Production;

    [EnumDataType(typeof(AssetType))]
    public AssetType AssetType { get; set; } = AssetType.Application;
}

public sealed record ProjectFindingStatsDto(
    Guid ProjectId,
    int Open,
    int P1,
    int P2,
    int P3,
    int P4,
    int Overdue,
    int InKev,
    int ForensicTriage,
    int Closed)
{
    public static ProjectFindingStatsDto Empty(Guid projectId) => new(projectId, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

public sealed record ProjectSummaryDto(ProjectDto Project, ProjectFindingStatsDto Stats, DateTimeOffset? LastImportAt);

public sealed record ApiKeyDto(
    Guid Id,
    Guid ProjectId,
    string Name,
    string Prefix,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt);

/// <summary>The secret is returned only once, at creation time.</summary>
public sealed record ApiKeyCreatedDto(ApiKeyDto Key, string Secret);

public sealed class CreateApiKeyRequest
{
    [Required(ErrorMessage = "El nombre es obligatorio.")]
    [StringLength(100, MinimumLength = 3)]
    public string Name { get; set; } = string.Empty;

    [Range(1, ProjectApiKey.MaxLifetimeDays)]
    public int ExpiresInDays { get; set; } = 90;
}

public sealed record SbomImportDto(
    Guid Id,
    Guid ProjectId,
    string SpecVersion,
    string? SerialNumber,
    SbomSource Source,
    string? SourceRef,
    string? FileName,
    string Sha256,
    int SizeBytes,
    int ComponentCount,
    int SkippedCount,
    SbomImportStatus Status,
    string? ErrorMessage,
    DateTimeOffset ImportedAt,
    DateTimeOffset? ProcessedAt);

public sealed record SbomImportResultDto(
    SbomImportDto Import,
    bool Created,
    int VexStatementsImported,
    ReconciliationResult Reconciliation,
    bool EnrichmentQueued);

public sealed record ReconciliationResult(
    int Created,
    int Reopened,
    int Closed,
    int ChangedByVex,
    int PriorityChanged,
    int SlaChanged,
    int AlertsCreated)
{
    public static ReconciliationResult Empty { get; } = new(0, 0, 0, 0, 0, 0, 0);

    public int TotalChanges => Created + Reopened + Closed + ChangedByVex + PriorityChanged + SlaChanged + AlertsCreated;

    public ReconciliationResult Add(ReconciliationResult other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return new(
            Created + other.Created,
            Reopened + other.Reopened,
            Closed + other.Closed,
            ChangedByVex + other.ChangedByVex,
            PriorityChanged + other.PriorityChanged,
            SlaChanged + other.SlaChanged,
            AlertsCreated + other.AlertsCreated);
    }
}
