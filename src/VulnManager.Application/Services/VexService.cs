using VulnManager.Application.Abstractions;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Packages;
using VulnManager.Domain.Vex;

namespace VulnManager.Application.Services;

/// <summary>VEX statements reduce noise: a justified "not_affected" closes findings and survives new SBOM imports.</summary>
public sealed class VexService(
    IVexRepository statements,
    IProjectRepository projects,
    ISbomImportRepository imports,
    IComponentRepository components,
    ICycloneDxParser parser,
    IUnitOfWork unitOfWork,
    AuditService audit,
    FindingReconciliationService reconciliation,
    TimeProvider time)
{
    public async Task<IReadOnlyList<VexStatementDto>> ListAsync(Actor actor, Guid projectId, bool includeRevoked, CancellationToken cancellationToken = default)
    {
        await EnsureProjectAsync(actor, projectId, cancellationToken);
        return (await statements.ListByProjectAsync(projectId, includeRevoked, cancellationToken)).Select(s => s.ToDto()).ToList();
    }

    public async Task<VexStatementDto> CreateAsync(Actor actor, Guid projectId, CreateVexStatementRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnsureTriage(actor);
        await EnsureProjectAsync(actor, projectId, cancellationToken);

        var draft = new VexStatementDraft(
            request.Status,
            request.Justification is null ? null : VexJustificationScheme.Cisa,
            string.IsNullOrWhiteSpace(request.Justification) ? null : request.Justification.Trim(),
            request.ImpactStatement,
            request.ActionStatement,
            request.VulnerabilityRef,
            string.IsNullOrWhiteSpace(request.ComponentPurl) ? null : request.ComponentPurl.Trim());

        VexStatement statement;
        try
        {
            statement = new VexStatement(projectId, draft, VexSource.Manual, null, null, null, actor.Id, time.GetUtcNow());
        }
        catch (DomainException ex)
        {
            throw new InvalidInputException(ex.Message, ex);
        }

        statements.Add(statement);
        audit.Record(actor, AuditActions.VexCreated, "vex_statement", statement.Id,
            new { projectId, statement.VulnerabilityRef, statement.ComponentPurl, statement.Status, statement.Justification });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await reconciliation.ReconcileProjectAsync(projectId, cancellationToken);
        return statement.ToDto();
    }

    public async Task RevokeAsync(Actor actor, Guid projectId, Guid statementId, CancellationToken cancellationToken = default)
    {
        EnsureTriage(actor);
        await EnsureProjectAsync(actor, projectId, cancellationToken);
        var statement = await statements.GetAsync(statementId, cancellationToken);
        if (statement is null || statement.ProjectId != projectId)
        {
            throw NotFoundException.For("Declaración VEX", statementId);
        }

        try
        {
            statement.Revoke(actor.Id, time.GetUtcNow());
        }
        catch (DomainException ex)
        {
            throw new ConflictException(ex.Message, ex);
        }

        audit.Record(actor, AuditActions.VexRevoked, "vex_statement", statement.Id, new { projectId });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await reconciliation.ReconcileProjectAsync(projectId, cancellationToken);
    }

    /// <summary>Imports a CycloneDX VEX document (a BOM whose "vulnerabilities" carry "analysis").</summary>
    public async Task<int> ImportCycloneDxAsync(Actor actor, Guid projectId, string json, CancellationToken cancellationToken = default)
    {
        EnsureTriage(actor);
        await EnsureProjectAsync(actor, projectId, cancellationToken);
        var parsed = parser.Parse(json);
        var refToPurl = parsed.Components.Where(c => c.BomRef is not null).GroupBy(c => c.BomRef!).ToDictionary(g => g.Key, g => g.First().Purl);
        var created = await AddFromBomAsync(actor, projectId, null, parsed.Vex, refToPurl, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);
        await reconciliation.ReconcileProjectAsync(projectId, cancellationToken);
        return created;
    }

    /// <summary>
    /// Creates statements from CycloneDX analysis entries (does not save). Identical active statements are skipped so
    /// re-importing the same VEX is idempotent. Mapping of analysis.state: not_affected and false_positive → NOT_AFFECTED,
    /// resolved* → FIXED, exploitable → AFFECTED, in_triage → UNDER_INVESTIGATION.
    /// </summary>
    internal async Task<int> AddFromBomAsync(
        Actor actor,
        Guid projectId,
        Guid? sourceImportId,
        IReadOnlyList<ParsedVexEntry> entries,
        IReadOnlyDictionary<string, string> refToPurl,
        CancellationToken cancellationToken)
    {
        if (entries.Count == 0)
        {
            return 0;
        }

        var inventoryRefs = await InventoryRefsAsync(projectId, cancellationToken);
        var existing = await statements.ListByProjectAsync(projectId, includeRevoked: false, cancellationToken);
        var now = time.GetUtcNow();
        var created = 0;

        foreach (var entry in entries)
        {
            var targets = entry.AffectsRefs.Count == 0
                ? new List<string?> { null }
                : entry.AffectsRefs.Select(r => ResolvePurl(r, refToPurl, inventoryRefs)).Where(p => p is not null).Distinct().ToList();

            foreach (var purl in targets)
            {
                var draft = ToDraft(entry, purl);
                if (draft is null || VexStatementRules.Validate(draft).Count > 0)
                {
                    continue;
                }

                var duplicate = existing.Any(s => s.VulnerabilityRef.Equals(draft.VulnerabilityRef, StringComparison.OrdinalIgnoreCase)
                                                  && s.ComponentPurl == Normalize(draft.ComponentPurl)
                                                  && s.Status == draft.Status
                                                  && s.Justification == draft.Justification
                                                  && s.ImpactStatement == (string.IsNullOrWhiteSpace(draft.ImpactStatement) ? null : draft.ImpactStatement.Trim()));
                if (duplicate)
                {
                    continue;
                }

                var statement = new VexStatement(projectId, draft, VexSource.CycloneDxVex, sourceImportId, entry.State, entry.Responses, actor.Id, now);
                statements.Add(statement);
                audit.Record(actor, AuditActions.VexCreated, "vex_statement", statement.Id,
                    new { projectId, statement.VulnerabilityRef, statement.ComponentPurl, statement.Status, source = "CYCLONEDX" });
                created++;
            }
        }

        return created;
    }

    private static VexStatementDraft? ToDraft(ParsedVexEntry entry, string? purl)
    {
        var detail = string.IsNullOrWhiteSpace(entry.Detail) ? null : entry.Detail.Trim();
        var justification = entry.Justification is not null && VexJustifications.CycloneDx.Contains(entry.Justification) ? entry.Justification : null;
        var responses = entry.Responses.Count == 0 ? null : $"Respuesta CycloneDX: {string.Join(", ", entry.Responses)}.";

        return entry.State switch
        {
            "not_affected" => new VexStatementDraft(VexStatus.NotAffected, justification is null ? null : VexJustificationScheme.CycloneDx, justification, detail, null, entry.VulnerabilityId, purl),
            "false_positive" => new VexStatementDraft(VexStatus.NotAffected, null, null, detail ?? "CycloneDX analysis.state = false_positive.", null, entry.VulnerabilityId, purl),
            "resolved" or "resolved_with_pedigree" => new VexStatementDraft(VexStatus.Fixed, null, null, detail, null, entry.VulnerabilityId, purl),
            "exploitable" => new VexStatementDraft(VexStatus.Affected, null, null, null, detail ?? responses, entry.VulnerabilityId, purl),
            "in_triage" => new VexStatementDraft(VexStatus.UnderInvestigation, null, null, detail, null, entry.VulnerabilityId, purl),
            _ => null,
        };
    }

    private static string? ResolvePurl(string reference, IReadOnlyDictionary<string, string> refToPurl, IReadOnlyDictionary<string, string> inventoryRefs)
    {
        if (refToPurl.TryGetValue(reference, out var purl) || inventoryRefs.TryGetValue(reference, out purl))
        {
            return purl;
        }

        // Some tools reference components by purl directly, or with a BOM-Link "urn:cdx:serial/version#bom-ref".
        var fragment = reference.Contains('#', StringComparison.Ordinal) ? reference[(reference.LastIndexOf('#') + 1)..] : reference;
        if (refToPurl.TryGetValue(fragment, out purl) || inventoryRefs.TryGetValue(fragment, out purl))
        {
            return purl;
        }

        return PackageUrl.TryParse(fragment, out var parsed) ? parsed.Coordinates : null;
    }

    private async Task<IReadOnlyDictionary<string, string>> InventoryRefsAsync(Guid projectId, CancellationToken cancellationToken)
    {
        var project = await projects.GetAsync(projectId, cancellationToken);
        if (project?.CurrentSbomImportId is not { } importId)
        {
            return new Dictionary<string, string>();
        }

        var import = await imports.GetAsync(importId, cancellationToken);
        if (import is null)
        {
            return new Dictionary<string, string>();
        }

        var componentById = (await components.GetByIdsAsync(import.Components.Select(c => c.ComponentId).ToList(), cancellationToken)).ToDictionary(c => c.Id);
        return import.Components
            .Where(c => c.BomRef is not null && componentById.ContainsKey(c.ComponentId))
            .GroupBy(c => c.BomRef!)
            .ToDictionary(g => g.Key, g => componentById[g.First().ComponentId].Purl);
    }

    private static string? Normalize(string? purl)
    {
        if (purl is null || !PackageUrl.TryParse(purl, out var parsed))
        {
            return purl;
        }

        return parsed.Version is null ? parsed.VersionlessCoordinates : parsed.Coordinates;
    }

    private async Task EnsureProjectAsync(Actor actor, Guid projectId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.CanAccessProject(projectId) || await projects.GetAsync(projectId, cancellationToken) is null)
        {
            throw NotFoundException.For("Proyecto", projectId);
        }
    }

    private static void EnsureTriage(Actor actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!actor.CanTriage)
        {
            throw new ForbiddenException("Se requiere rol Analyst o Admin para gestionar VEX.");
        }
    }
}
