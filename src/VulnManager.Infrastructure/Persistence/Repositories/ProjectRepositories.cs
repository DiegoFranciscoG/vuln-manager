using Microsoft.EntityFrameworkCore;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Domain.Entities;

namespace VulnManager.Infrastructure.Persistence.Repositories;

public sealed class ProjectRepository(VulnManagerDbContext db) : IProjectRepository
{
    public Task<Project?> GetAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.Projects.FirstOrDefaultAsync(p => p.Id == id, cancellationToken);

    public async Task<IReadOnlyList<Project>> ListAsync(bool includeArchived, CancellationToken cancellationToken = default) =>
        await db.Projects.Where(p => includeArchived || p.ArchivedAt == null).OrderBy(p => p.Name).ToListAsync(cancellationToken);

    public Task<bool> NameExistsAsync(string name, Guid? excludeId, CancellationToken cancellationToken = default)
    {
        var pattern = LikePattern.Escape(name);
        return db.Projects.AnyAsync(p => EF.Functions.ILike(p.Name, pattern, LikePattern.EscapeCharacter) && (excludeId == null || p.Id != excludeId), cancellationToken);
    }

    public void Add(Project project) => db.Projects.Add(project);
}

public sealed class ApiKeyRepository(VulnManagerDbContext db) : IApiKeyRepository
{
    public Task<ProjectApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken = default) =>
        db.ProjectApiKeys.FirstOrDefaultAsync(k => k.KeyPrefix == prefix, cancellationToken);

    public Task<ProjectApiKey?> GetAsync(Guid projectId, Guid keyId, CancellationToken cancellationToken = default) =>
        db.ProjectApiKeys.FirstOrDefaultAsync(k => k.Id == keyId && k.ProjectId == projectId, cancellationToken);

    public async Task<IReadOnlyList<ProjectApiKey>> ListByProjectAsync(Guid projectId, CancellationToken cancellationToken = default) =>
        await db.ProjectApiKeys.AsNoTracking().Where(k => k.ProjectId == projectId).OrderByDescending(k => k.CreatedAt).ToListAsync(cancellationToken);

    public void Add(ProjectApiKey key) => db.ProjectApiKeys.Add(key);
}

public sealed class SbomImportRepository(VulnManagerDbContext db) : ISbomImportRepository
{
    public Task<SbomImport?> FindByHashAsync(Guid projectId, string sha256, CancellationToken cancellationToken = default) =>
        db.SbomImports.AsNoTracking().FirstOrDefaultAsync(s => s.ProjectId == projectId && s.Sha256 == sha256, cancellationToken);

    public Task<SbomImport?> GetAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.SbomImports.AsNoTracking().Include(s => s.Components).FirstOrDefaultAsync(s => s.Id == id, cancellationToken);

    public async Task<IReadOnlyList<SbomImport>> ListByProjectAsync(Guid projectId, int take, CancellationToken cancellationToken = default) =>
        await db.SbomImports.AsNoTracking().Where(s => s.ProjectId == projectId).OrderByDescending(s => s.ImportedAt).Take(take).ToListAsync(cancellationToken);

    public async Task<IReadOnlyList<Guid>> GetInventoryComponentIdsAsync(Guid projectId, CancellationToken cancellationToken = default)
    {
        var currentImport = db.Projects.Where(p => p.Id == projectId && p.CurrentSbomImportId != null).Select(p => p.CurrentSbomImportId!.Value);
        return await db.SbomComponents.Where(c => currentImport.Contains(c.SbomImportId)).Select(c => c.ComponentId).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Guid>> GetProjectsUsingComponentsAsync(IReadOnlyCollection<Guid> componentIds, CancellationToken cancellationToken = default)
    {
        if (componentIds.Count == 0)
        {
            return [];
        }

        var ids = componentIds.ToList();
        return await (from p in db.Projects
                      where p.ArchivedAt == null && p.CurrentSbomImportId != null
                      where db.SbomComponents.Any(c => c.SbomImportId == p.CurrentSbomImportId && ids.Contains(c.ComponentId))
                      select p.Id).ToListAsync(cancellationToken);
    }

    public void Add(SbomImport sbomImport) => db.SbomImports.Add(sbomImport);
}

public sealed class ComponentRepository(VulnManagerDbContext db) : IComponentRepository
{
    public async Task<Dictionary<string, Component>> GetByPurlsAsync(IReadOnlyCollection<string> purls, CancellationToken cancellationToken = default)
    {
        var list = purls.ToList();
        return await db.Components.Where(c => list.Contains(c.Purl)).ToDictionaryAsync(c => c.Purl, StringComparer.Ordinal, cancellationToken);
    }

    public async Task<IReadOnlyList<Component>> GetByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default)
    {
        var list = ids.ToList();
        return await db.Components.Where(c => list.Contains(c.Id)).ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Component>> ListDueForOsvAsync(Guid? projectId, DateTimeOffset checkedBefore, int take, CancellationToken cancellationToken = default)
    {
        var currentImports = db.Projects
            .Where(p => p.ArchivedAt == null && p.CurrentSbomImportId != null && (projectId == null || p.Id == projectId))
            .Select(p => p.CurrentSbomImportId!.Value);
        var inventory = db.SbomComponents.Where(c => currentImports.Contains(c.SbomImportId)).Select(c => c.ComponentId);
        return await db.Components
            .Where(c => inventory.Contains(c.Id) && (c.VulnsCheckedAt == null || c.VulnsCheckedAt < checkedBefore))
            .OrderBy(c => c.VulnsCheckedAt != null)
            .ThenBy(c => c.VulnsCheckedAt)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    public void Add(Component component) => db.Components.Add(component);
}
