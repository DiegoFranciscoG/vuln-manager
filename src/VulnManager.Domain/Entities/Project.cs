using VulnManager.Domain.Common;

namespace VulnManager.Domain.Entities;

public sealed class Project
{
    private Project()
    {
    }

    public Project(string name, string? description, string? repositoryUrl, Exposure exposure, DeploymentEnvironment environment, AssetType assetType, DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        CreatedAt = now;
        Update(name, description, repositoryUrl, exposure, environment, assetType, now);
    }

    public Guid Id { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string? Description { get; private set; }

    public string? RepositoryUrl { get; private set; }

    public Exposure Exposure { get; private set; }

    public DeploymentEnvironment Environment { get; private set; }

    public AssetType AssetType { get; private set; }

    /// <summary>Inventory in force: the latest processed SBOM.</summary>
    public Guid? CurrentSbomImportId { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public DateTimeOffset? ArchivedAt { get; private set; }

    public uint Version { get; private set; }

    public void Update(string name, string? description, string? repositoryUrl, Exposure exposure, DeploymentEnvironment environment, AssetType assetType, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 100)
        {
            throw new DomainException("El nombre del proyecto es obligatorio (máximo 100 caracteres).");
        }

        if (repositoryUrl is not null
            && (!Uri.TryCreate(repositoryUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || repositoryUrl.Length > 300))
        {
            throw new DomainException("La URL del repositorio debe ser https (máximo 300 caracteres).");
        }

        if (description?.Length > 500)
        {
            throw new DomainException("La descripción admite como máximo 500 caracteres.");
        }

        Name = name.Trim();
        Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        RepositoryUrl = repositoryUrl;
        Exposure = exposure;
        Environment = environment;
        AssetType = assetType;
        UpdatedAt = now;
    }

    public void SetCurrentInventory(Guid sbomImportId, DateTimeOffset now)
    {
        CurrentSbomImportId = sbomImportId;
        UpdatedAt = now;
    }

    public void Archive(DateTimeOffset now)
    {
        ArchivedAt ??= now;
        UpdatedAt = now;
    }
}
