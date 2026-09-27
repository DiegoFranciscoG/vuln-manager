using System.Security.Cryptography;
using System.Text;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Packages;

namespace VulnManager.Application.Services;

/// <summary>
/// Ingests CycloneDX JSON SBOMs (API from CI pipelines or UI upload). Idempotent by SHA-256 per project; the raw document
/// is not stored (only its hash and the extracted components), which also discards author metadata (LOPDP minimization).
/// </summary>
public sealed class SbomImportService(
    IProjectRepository projects,
    ISbomImportRepository imports,
    IComponentRepository components,
    ICycloneDxParser parser,
    IUnitOfWork unitOfWork,
    AuditService audit,
    VexService vex,
    FindingReconciliationService reconciliation,
    ISyncDispatcher syncDispatcher,
    TimeProvider time)
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public async Task<SbomImportResultDto> ImportAsync(
        Actor actor,
        Guid projectId,
        ReadOnlyMemory<byte> content,
        string? fileName,
        SbomSource source,
        string? sourceRef,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.CanAccessProject(projectId))
        {
            throw NotFoundException.For("Proyecto", projectId);
        }

        if (actor.Type != ActorType.ApiKey && !actor.CanTriage)
        {
            throw new ForbiddenException("Se requiere rol Analyst o Admin, o una clave de ingesta del proyecto.");
        }

        var project = await projects.GetAsync(projectId, cancellationToken) ?? throw NotFoundException.For("Proyecto", projectId);
        if (project.ArchivedAt is not null)
        {
            throw new ConflictException("El proyecto está archivado.");
        }

        if (content.Length is 0 or > SbomImport.MaxSizeBytes)
        {
            throw new InvalidInputException($"El SBOM debe pesar entre 1 byte y {SbomImport.MaxSizeBytes / (1024 * 1024)} MiB.");
        }

        var sha256 = Convert.ToHexStringLower(SHA256.HashData(content.Span));
        var existing = await imports.FindByHashAsync(projectId, sha256, cancellationToken);
        if (existing is not null)
        {
            return new SbomImportResultDto(existing.ToDto(), false, 0, ReconciliationResult.Empty, false);
        }

        string json;
        try
        {
            json = StrictUtf8.GetString(content.Span);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidInputException("El SBOM debe estar codificado en UTF-8.", ex);
        }

        var parsed = parser.Parse(json);
        var now = time.GetUtcNow();
        var import = new SbomImport(projectId, parsed.SpecVersion, Clip(parsed.SerialNumber, 100), parsed.Version, source,
            SanitizeSourceRef(sourceRef), SanitizeFileName(fileName), sha256, content.Length, actor.Id, now);

        var purls = parsed.Components.Select(c => c.Purl).Distinct(StringComparer.Ordinal).ToList();
        var known = await components.GetByPurlsAsync(purls, cancellationToken);
        foreach (var parsedComponent in parsed.Components)
        {
            if (!known.TryGetValue(parsedComponent.Purl, out var component))
            {
                component = new Component(PackageUrl.Parse(parsedComponent.Purl), now);
                components.Add(component);
                known[component.Purl] = component;
            }

            import.AddComponent(component.Id, parsedComponent.BomRef, parsedComponent.Scope);
        }

        import.SetSkipped(parsed.SkippedComponents);
        import.MarkProcessed(now);
        imports.Add(import);
        project.SetCurrentInventory(import.Id, now);

        var refToPurl = parsed.Components.Where(c => c.BomRef is not null).GroupBy(c => c.BomRef!).ToDictionary(g => g.Key, g => g.First().Purl);
        var vexCreated = await vex.AddFromBomAsync(actor, projectId, import.Id, parsed.Vex, refToPurl, cancellationToken);

        audit.Record(actor, AuditActions.SbomImported, "sbom_import", import.Id, new
        {
            projectId,
            import.SpecVersion,
            import.ComponentCount,
            import.SkippedCount,
            vexStatements = vexCreated,
            source,
        });

        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (ConflictException)
        {
            // The same SBOM was imported concurrently: return the winner (idempotent behaviour).
            var winner = await imports.FindByHashAsync(projectId, sha256, cancellationToken);
            if (winner is null)
            {
                throw;
            }

            return new SbomImportResultDto(winner.ToDto(), false, 0, ReconciliationResult.Empty, false);
        }

        var result = await reconciliation.ReconcileProjectAsync(projectId, cancellationToken);
        var queued = syncDispatcher.TryEnqueue(new SyncRequest(SyncSource.Osv, SyncTrigger.SbomImport, projectId));
        return new SbomImportResultDto(import.ToDto(), true, vexCreated, result, queued);
    }

    public async Task<IReadOnlyList<SbomImportDto>> ListAsync(Actor actor, Guid projectId, int take, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.CanAccessProject(projectId) || await projects.GetAsync(projectId, cancellationToken) is null)
        {
            throw NotFoundException.For("Proyecto", projectId);
        }

        return (await imports.ListByProjectAsync(projectId, Math.Clamp(take, 1, 100), cancellationToken)).Select(i => i.ToDto()).ToList();
    }

    public async Task<SbomImportDto> GetAsync(Actor actor, Guid importId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var import = await imports.GetAsync(importId, cancellationToken);
        if (import is null || !actor.CanAccessProject(import.ProjectId))
        {
            throw NotFoundException.For("Importación", importId);
        }

        return import.ToDto();
    }

    /// <summary>Keeps only the file name (no path) with a conservative character whitelist.</summary>
    public static string? SanitizeFileName(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return null;
        }

        var name = fileName.Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
        var cleaned = new string(name.Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_').ToArray()).TrimStart('.');
        return cleaned.Length == 0 ? null : Clip(cleaned, 255);
    }

    private static string? SanitizeSourceRef(string? sourceRef)
    {
        if (string.IsNullOrWhiteSpace(sourceRef))
        {
            return null;
        }

        var trimmed = sourceRef.Trim();
        return trimmed.Any(char.IsControl) ? null : Clip(trimmed, 300);
    }

    private static string? Clip(string? value, int max) => value is null ? null : value.Length > max ? value[..max] : value;
}
