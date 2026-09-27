using System.Security.Cryptography;
using System.Text;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Services;

/// <summary>
/// Project-scoped ingestion keys ("vmk_{prefix}_{secret}"). Only a SHA-256 hash is stored: the secret has 256 bits of
/// entropy, so a slow password hash is unnecessary. Comparison is constant-time.
/// </summary>
public sealed class ApiKeyService(
    IApiKeyRepository keys,
    IProjectRepository projects,
    IUnitOfWork unitOfWork,
    AuditService audit,
    TimeProvider time)
{
    public const string TokenPrefix = "vmk_";
    private const string PrefixAlphabet = "abcdefghijkmnpqrstuvwxyz23456789";
    private static readonly TimeSpan LastUsedGranularity = TimeSpan.FromMinutes(5);

    public async Task<ApiKeyCreatedDto> CreateAsync(Actor actor, Guid projectId, CreateApiKeyRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede crear claves de ingesta.");
        }

        _ = await projects.GetAsync(projectId, cancellationToken) ?? throw NotFoundException.For("Proyecto", projectId);

        var prefix = RandomNumberGenerator.GetString(PrefixAlphabet, ProjectApiKey.PrefixLength);
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var token = $"{TokenPrefix}{prefix}_{secret}";
        var now = time.GetUtcNow();
        var key = new ProjectApiKey(projectId, request.Name, prefix, Hash(token), actor.Id, now, now.AddDays(request.ExpiresInDays));
        keys.Add(key);
        audit.Record(actor, AuditActions.ApiKeyCreated, "project_api_key", key.Id, new { projectId, key.KeyPrefix, key.ExpiresAt });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new ApiKeyCreatedDto(key.ToDto(), token);
    }

    public async Task<IReadOnlyList<ApiKeyDto>> ListAsync(Actor actor, Guid projectId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede ver las claves de ingesta.");
        }

        return (await keys.ListByProjectAsync(projectId, cancellationToken)).Select(k => k.ToDto()).ToList();
    }

    public async Task RevokeAsync(Actor actor, Guid projectId, Guid keyId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede revocar claves de ingesta.");
        }

        var key = await keys.GetAsync(projectId, keyId, cancellationToken) ?? throw NotFoundException.For("Clave", keyId);
        key.Revoke(time.GetUtcNow());
        audit.Record(actor, AuditActions.ApiKeyRevoked, "project_api_key", key.Id, new { projectId, key.KeyPrefix });
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    /// <summary>Returns the actor for a valid, unexpired, unrevoked key, or null.</summary>
    public async Task<Actor?> AuthenticateAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (token is null || token.Length > 200 || !token.StartsWith(TokenPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var parts = token[TokenPrefix.Length..].Split('_', 2);
        if (parts.Length != 2 || parts[0].Length != ProjectApiKey.PrefixLength)
        {
            return null;
        }

        var key = await keys.FindByPrefixAsync(parts[0], cancellationToken);
        var now = time.GetUtcNow();
        if (key is null || !CryptographicOperations.FixedTimeEquals(key.KeyHash, Hash(token)) || !key.IsUsable(now))
        {
            return null;
        }

        if (key.LastUsedAt is null || now - key.LastUsedAt > LastUsedGranularity)
        {
            key.MarkUsed(now);
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }

        return new Actor(ActorType.ApiKey, $"api-key:{key.KeyPrefix}", [], key.ProjectId);
    }

    private static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
}
