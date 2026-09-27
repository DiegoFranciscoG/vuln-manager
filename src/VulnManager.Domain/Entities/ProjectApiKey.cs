using VulnManager.Domain.Common;

namespace VulnManager.Domain.Entities;

/// <summary>Project-scoped ingestion key for CI pipelines. Only the SHA-256 of the 32-byte random secret is stored.</summary>
public sealed class ProjectApiKey
{
    public const int PrefixLength = 8;
    public const int MaxLifetimeDays = 365;

    private ProjectApiKey()
    {
    }

    public ProjectApiKey(Guid projectId, string name, string keyPrefix, byte[] keyHash, string createdBy, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(keyHash);
        if (string.IsNullOrWhiteSpace(name) || name.Length > 100)
        {
            throw new DomainException("El nombre de la clave es obligatorio (máximo 100 caracteres).");
        }

        if (expiresAt <= now || expiresAt > now.AddDays(MaxLifetimeDays))
        {
            throw new DomainException($"La clave debe expirar dentro de 1 a {MaxLifetimeDays} días.");
        }

        if (keyPrefix.Length != PrefixLength || keyHash.Length != 32)
        {
            throw new DomainException("Formato de clave inválido.");
        }

        Id = Guid.CreateVersion7(now);
        ProjectId = projectId;
        Name = name.Trim();
        KeyPrefix = keyPrefix;
        KeyHash = keyHash;
        CreatedBy = createdBy;
        CreatedAt = now;
        ExpiresAt = expiresAt;
    }

    public Guid Id { get; private set; }

    public Guid ProjectId { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string KeyPrefix { get; private set; } = string.Empty;

    public byte[] KeyHash { get; private set; } = [];

    public string CreatedBy { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? LastUsedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public bool IsUsable(DateTimeOffset now) => RevokedAt is null && ExpiresAt > now;

    public void MarkUsed(DateTimeOffset now) => LastUsedAt = now;

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}
