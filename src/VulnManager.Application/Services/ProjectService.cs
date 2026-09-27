using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Services;

public sealed class ProjectService(
    IProjectRepository projects,
    ISbomImportRepository imports,
    IFindingRepository findings,
    IUnitOfWork unitOfWork,
    AuditService audit,
    FindingReconciliationService reconciliation,
    TimeProvider time)
{
    public async Task<IReadOnlyList<ProjectSummaryDto>> ListAsync(Actor actor, bool includeArchived = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var all = await projects.ListAsync(includeArchived, cancellationToken);
        var stats = (await findings.GetStatsAsync(time.GetUtcNow(), cancellationToken)).ToDictionary(s => s.ProjectId);
        var result = new List<ProjectSummaryDto>();
        foreach (var project in all.Where(p => actor.CanAccessProject(p.Id)))
        {
            var lastImports = await imports.ListByProjectAsync(project.Id, 1, cancellationToken);
            var lastImportAt = lastImports.Count > 0 ? lastImports[0].ImportedAt : (DateTimeOffset?)null;
            result.Add(new ProjectSummaryDto(project.ToDto(), stats.GetValueOrDefault(project.Id) ?? ProjectFindingStatsDto.Empty(project.Id), lastImportAt));
        }

        return result;
    }

    public async Task<ProjectDto> GetAsync(Actor actor, Guid id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var project = await projects.GetAsync(id, cancellationToken);
        if (project is null || !actor.CanAccessProject(id))
        {
            throw NotFoundException.For("Proyecto", id);
        }

        return project.ToDto();
    }

    public async Task<ProjectDto> CreateAsync(Actor actor, ProjectRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        EnsureAdmin(actor);

        if (await projects.NameExistsAsync(request.Name.Trim(), null, cancellationToken))
        {
            throw new ConflictException($"Ya existe un proyecto llamado '{request.Name.Trim()}'.");
        }

        var project = new Project(request.Name, request.Description, request.RepositoryUrl, request.Exposure, request.Environment, request.AssetType, time.GetUtcNow());
        projects.Add(project);
        audit.Record(actor, AuditActions.ProjectCreated, "project", project.Id, new { project.Name, project.Exposure, project.Environment });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return project.ToDto();
    }

    /// <summary>BOD 26-04 timelines are dynamic: changing the exposure recalculates priorities and deadlines.</summary>
    public async Task<ProjectDto> UpdateAsync(Actor actor, Guid id, ProjectRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        EnsureAdmin(actor);

        var project = await projects.GetAsync(id, cancellationToken) ?? throw NotFoundException.For("Proyecto", id);
        if (await projects.NameExistsAsync(request.Name.Trim(), id, cancellationToken))
        {
            throw new ConflictException($"Ya existe un proyecto llamado '{request.Name.Trim()}'.");
        }

        var exposureChanged = project.Exposure != request.Exposure;
        var before = new { project.Name, project.Exposure, project.Environment, project.AssetType };
        project.Update(request.Name, request.Description, request.RepositoryUrl, request.Exposure, request.Environment, request.AssetType, time.GetUtcNow());
        audit.Record(actor, AuditActions.ProjectUpdated, "project", project.Id, new { before, after = new { project.Name, project.Exposure, project.Environment, project.AssetType } });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        if (exposureChanged)
        {
            await reconciliation.ReconcileProjectAsync(project.Id, cancellationToken);
        }

        return project.ToDto();
    }

    public async Task ArchiveAsync(Actor actor, Guid id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        EnsureAdmin(actor);
        var project = await projects.GetAsync(id, cancellationToken) ?? throw NotFoundException.For("Proyecto", id);
        project.Archive(time.GetUtcNow());
        audit.Record(actor, AuditActions.ProjectArchived, "project", project.Id);
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    private static void EnsureAdmin(Actor actor)
    {
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede gestionar proyectos.");
        }
    }
}
