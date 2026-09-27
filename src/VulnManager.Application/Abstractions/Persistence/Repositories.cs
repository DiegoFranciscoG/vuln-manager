using VulnManager.Application.Dtos;
using VulnManager.Application.Common;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Abstractions.Persistence;

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public interface IProjectRepository
{
    Task<Project?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Project>> ListAsync(bool includeArchived, CancellationToken cancellationToken = default);

    Task<bool> NameExistsAsync(string name, Guid? excludeId, CancellationToken cancellationToken = default);

    void Add(Project project);
}

public interface IApiKeyRepository
{
    Task<ProjectApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken = default);

    Task<ProjectApiKey?> GetAsync(Guid projectId, Guid keyId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProjectApiKey>> ListByProjectAsync(Guid projectId, CancellationToken cancellationToken = default);

    void Add(ProjectApiKey key);
}

public interface ISbomImportRepository
{
    Task<SbomImport?> FindByHashAsync(Guid projectId, string sha256, CancellationToken cancellationToken = default);

    Task<SbomImport?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SbomImport>> ListByProjectAsync(Guid projectId, int take, CancellationToken cancellationToken = default);

    /// <summary>Component ids of the project's current inventory (latest processed SBOM).</summary>
    Task<IReadOnlyList<Guid>> GetInventoryComponentIdsAsync(Guid projectId, CancellationToken cancellationToken = default);

    /// <summary>Projects whose current inventory contains any of the components.</summary>
    Task<IReadOnlyList<Guid>> GetProjectsUsingComponentsAsync(IReadOnlyCollection<Guid> componentIds, CancellationToken cancellationToken = default);

    void Add(SbomImport sbomImport);
}

public interface IComponentRepository
{
    Task<Dictionary<string, Component>> GetByPurlsAsync(IReadOnlyCollection<string> purls, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Component>> GetByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default);

    /// <summary>Components in any current inventory that were never checked against OSV or were checked before <paramref name="checkedBefore"/>.</summary>
    Task<IReadOnlyList<Component>> ListDueForOsvAsync(Guid? projectId, DateTimeOffset checkedBefore, int take, CancellationToken cancellationToken = default);

    void Add(Component component);
}

public interface IVulnerabilityRepository
{
    Task<Dictionary<string, Vulnerability>> GetByExternalIdsAsync(IReadOnlyCollection<string> externalIds, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Vulnerability>> GetByIdsAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default);

    Task<Vulnerability?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>Vulnerabilities with a CVE id matched to at least one component (the set worth enriching).</summary>
    Task<IReadOnlyList<Vulnerability>> ListMatchedWithCveAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ComponentVulnerability>> GetMatchesAsync(IReadOnlyCollection<Guid> componentIds, CancellationToken cancellationToken = default);

    void Add(Vulnerability vulnerability);

    void AddMatch(ComponentVulnerability match);

    void RemoveMatch(ComponentVulnerability match);
}

public interface IKevRepository
{
    Task<Dictionary<string, KevEntry>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Dictionary<string, KevEntry>> GetByCveIdsAsync(IReadOnlyCollection<string> cveIds, CancellationToken cancellationToken = default);

    void Add(KevEntry entry);
}

public interface IFindingRepository
{
    /// <summary>Tracked findings of a project (without history), used by the reconciliation.</summary>
    Task<IReadOnlyList<Finding>> ListByProjectAsync(Guid projectId, CancellationToken cancellationToken = default);

    Task<Finding?> GetAsync(Guid id, bool includeHistory, CancellationToken cancellationToken = default);

    Task<PagedResult<FindingListItemDto>> QueryAsync(FindingQuery query, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<FindingListItemDto>> ExportAsync(FindingQuery query, DateTimeOffset now, int maxRows, CancellationToken cancellationToken = default);

    Task<FindingDetailDto?> GetDetailAsync(Guid id, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Open findings whose SLA is due before <paramref name="dueBefore"/>.</summary>
    Task<IReadOnlyList<Finding>> ListOpenDueBeforeAsync(DateTimeOffset dueBefore, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Guid>> GetProjectsWithVulnerabilitiesAsync(IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ProjectFindingStatsDto>> GetStatsAsync(DateTimeOffset now, CancellationToken cancellationToken = default);

    void Add(Finding finding);
}

public interface IVexRepository
{
    Task<IReadOnlyList<VexStatement>> ListByProjectAsync(Guid projectId, bool includeRevoked, CancellationToken cancellationToken = default);

    Task<VexStatement?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    void Add(VexStatement statement);
}

public interface IPriorityRuleRepository
{
    Task<PriorityRuleVersion?> GetActiveAsync(CancellationToken cancellationToken = default);

    Task<PriorityRuleVersion?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PriorityRuleVersion>> ListAsync(CancellationToken cancellationToken = default);

    Task<int> MaxVersionAsync(CancellationToken cancellationToken = default);

    void Add(PriorityRuleVersion rule);
}

public interface IAlertRepository
{
    Task<HashSet<string>> ExistingKeysAsync(IReadOnlyCollection<string> dedupKeys, CancellationToken cancellationToken = default);

    Task<Alert?> GetAsync(Guid id, CancellationToken cancellationToken = default);

    Task<PagedResult<AlertDto>> ListAsync(Guid? projectId, bool onlyOpen, int page, int pageSize, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<Alert>> ListUndeliveredAsync(int take, CancellationToken cancellationToken = default);

    void Add(Alert alert);
}

public interface ISyncRunRepository
{
    Task<SyncRun?> LatestSuccessfulAsync(SyncSource source, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SyncRun>> ListRecentAsync(int take, CancellationToken cancellationToken = default);

    Task<int> FailStaleRunsAsync(DateTimeOffset startedBefore, DateTimeOffset now, CancellationToken cancellationToken = default);

    /// <summary>Inserts a RUNNING row. Returns false when another run of the same source is already in progress.</summary>
    Task<bool> TryStartAsync(SyncRun run, CancellationToken cancellationToken = default);

    Task CompleteAsync(SyncRun run, CancellationToken cancellationToken = default);
}

public interface IAuditLogRepository
{
    void Add(AuditLogEntry entry);

    Task<PagedResult<AuditEntryDto>> ListAsync(int page, int pageSize, CancellationToken cancellationToken = default);

    Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}
