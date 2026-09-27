using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Options;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Packages;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Sla;
using VulnManager.Domain.Vex;

namespace VulnManager.Application.Services;

/// <summary>
/// Brings a project's findings in line with its current inventory, the OSV matches, VEX statements and the active rule.
/// Deterministic and idempotent: running it twice without new facts changes nothing.
/// </summary>
public sealed partial class FindingReconciliationService(
    IProjectRepository projects,
    ISbomImportRepository imports,
    IComponentRepository components,
    IVulnerabilityRepository vulnerabilities,
    IKevRepository kev,
    IFindingRepository findings,
    IVexRepository vexStatements,
    IPriorityRuleRepository rules,
    IAlertRepository alerts,
    IUnitOfWork unitOfWork,
    TimeProvider time,
    IOptions<FindingOptions> options,
    ILogger<FindingReconciliationService> logger)
{
    private readonly int _maxAcceptanceDays = options.Value.RiskAcceptanceMaxDays;

    public async Task<ReconciliationResult> ReconcileAllAsync(CancellationToken cancellationToken = default)
    {
        var total = ReconciliationResult.Empty;
        foreach (var project in await projects.ListAsync(includeArchived: false, cancellationToken))
        {
            total = total.Add(await ReconcileProjectAsync(project.Id, cancellationToken));
        }

        return total;
    }

    public async Task<ReconciliationResult> ReconcileProjectsAsync(IEnumerable<Guid> projectIds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(projectIds);
        var total = ReconciliationResult.Empty;
        foreach (var projectId in projectIds.Distinct())
        {
            total = total.Add(await ReconcileProjectAsync(projectId, cancellationToken));
        }

        return total;
    }

    public async Task<ReconciliationResult> ReconcileProjectAsync(Guid projectId, CancellationToken cancellationToken = default)
    {
        var project = await projects.GetAsync(projectId, cancellationToken) ?? throw NotFoundException.For("Proyecto", projectId);
        var rule = await rules.GetActiveAsync(cancellationToken)
                   ?? throw new InvalidOperationException("There is no active priority rule; the database seed did not run.");
        var ruleSet = rule.ToRuleSet();
        var slaSettings = rule.ToSlaSettings();
        var now = time.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);

        var inventory = project.ArchivedAt is null
            ? (await imports.GetInventoryComponentIdsAsync(projectId, cancellationToken)).ToHashSet()
            : [];
        var matches = await vulnerabilities.GetMatchesAsync(inventory, cancellationToken);
        var existing = await findings.ListByProjectAsync(projectId, cancellationToken);

        var vulnerabilityIds = matches.Select(m => m.VulnerabilityId).Concat(existing.Select(f => f.VulnerabilityId)).Distinct().ToList();
        var vulnerabilityById = (await vulnerabilities.GetByIdsAsync(vulnerabilityIds, cancellationToken)).ToDictionary(v => v.Id);
        var componentById = (await components.GetByIdsAsync(inventory.ToList(), cancellationToken)).ToDictionary(c => c.Id);
        var cveIds = vulnerabilityById.Values.Where(v => v.CveId is not null).Select(v => v.CveId!).Distinct().ToList();
        var kevByCve = await kev.GetByCveIdsAsync(cveIds, cancellationToken);
        var vexCandidates = (await vexStatements.ListByProjectAsync(projectId, includeRevoked: false, cancellationToken))
            .Select(s => s.ToCandidate())
            .ToList();

        var active = matches
            .Where(m => vulnerabilityById.TryGetValue(m.VulnerabilityId, out var v) && v.WithdrawnAt is null && componentById.ContainsKey(m.ComponentId))
            .ToDictionary(m => (m.ComponentId, m.VulnerabilityId));
        var findingByKey = existing.ToDictionary(f => (f.ComponentId, f.VulnerabilityId));

        int created = 0, reopened = 0, closed = 0, changedByVex = 0, priorityChanged = 0, slaChanged = 0;
        var pendingAlerts = new List<Alert>();

        foreach (var (key, match) in active)
        {
            var vulnerability = vulnerabilityById[key.VulnerabilityId];
            var component = componentById[key.ComponentId];
            var purl = PackageUrl.Parse(component.Purl);
            var statement = VexMatcher.SelectApplicable(vexCandidates, vulnerability.ExternalId, vulnerability.Aliases, purl);
            var isNew = false;

            if (!findingByKey.TryGetValue(key, out var finding))
            {
                finding = Finding.Detect(projectId, key.ComponentId, key.VulnerabilityId, project.CurrentSbomImportId!.Value, now);
                findings.Add(finding);
                findingByKey[key] = finding;
                created++;
                isNew = true;
            }
            else if (finding.Status == FindingStatus.Fixed && statement?.Status != VexStatus.Fixed)
            {
                finding.ChangeStatus(FindingStatus.New, StatusChangeSource.SbomImport, Finding.SystemActor,
                    "El componente vulnerable volvió a aparecer en el SBOM vigente.", null, null, now, _maxAcceptanceDays);
                reopened++;
            }

            finding.MarkSeen(now);

            if (finding.Status == FindingStatus.Accepted && finding.RiskAcceptedUntil < today)
            {
                finding.ChangeStatus(FindingStatus.New, StatusChangeSource.Expiry, Finding.SystemActor,
                    "Venció la aceptación de riesgo.", null, null, now, _maxAcceptanceDays);
            }

            if (ApplyVex(finding, statement, now))
            {
                changedByVex++;
            }

            var kevEntry = kevByCve.TryGetValue(vulnerability.CveId ?? string.Empty, out var entry) && entry.RemovedAt is null ? entry : null;
            var decision = PriorityEngine.Evaluate(ruleSet, BuildPriorityInputs(project, vulnerability, kevEntry, match));
            if (finding.ApplyPriority(decision.Level, rule.Id, AppJson.Serialize(ToExplanation(rule, ruleSet, decision, vulnerability, project, match)), now) && !isNew)
            {
                priorityChanged++;
            }

            var sla = SlaCalculator.Calculate(slaSettings, BuildSlaInputs(project, vulnerability, kevEntry, finding));
            if (finding.ApplySla(sla, AppJson.Serialize(ToExplanation(sla, project, vulnerability)), now) && !isNew)
            {
                slaChanged++;
            }

            if (isNew && finding.Status == FindingStatus.New)
            {
                pendingAlerts.AddRange(AlertsForNewFinding(project, finding, vulnerability, component));
            }
        }

        foreach (var finding in existing.Where(f => f.Status != FindingStatus.Fixed && !active.ContainsKey((f.ComponentId, f.VulnerabilityId))))
        {
            var stillInInventory = inventory.Contains(finding.ComponentId);
            finding.ChangeStatus(
                FindingStatus.Fixed,
                stillInInventory ? StatusChangeSource.Sync : StatusChangeSource.SbomImport,
                Finding.SystemActor,
                stillInInventory ? "El aviso fue retirado o ya no aplica a esta versión." : "El componente ya no está en el SBOM vigente.",
                null,
                null,
                now,
                _maxAcceptanceDays);
            closed++;
        }

        var alertsCreated = await AddNewAlertsAsync(pendingAlerts, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        var result = new ReconciliationResult(created, reopened, closed, changedByVex, priorityChanged, slaChanged, alertsCreated);
        if (result.TotalChanges > 0)
        {
            LogReconciled(logger, projectId, created, reopened, closed, changedByVex, priorityChanged, slaChanged, alertsCreated);
        }

        return result;
    }

    private bool ApplyVex(Finding finding, VexCandidate? statement, DateTimeOffset now)
    {
        switch (statement?.Status)
        {
            case VexStatus.NotAffected when finding.Status is not FindingStatus.NotAffected and not FindingStatus.Fixed:
                finding.ChangeStatus(FindingStatus.NotAffected, StatusChangeSource.Vex, Finding.SystemActor,
                    "Declaración VEX: el producto no está afectado.", null, statement.Id, now, _maxAcceptanceDays);
                return true;
            case VexStatus.NotAffected when finding.Status == FindingStatus.NotAffected && finding.VexStatementId != statement.Id:
                finding.RelinkVex(statement.Id, now);
                return true;
            case VexStatus.Fixed when finding.Status != FindingStatus.Fixed:
                finding.ChangeStatus(FindingStatus.Fixed, StatusChangeSource.Vex, Finding.SystemActor,
                    "Declaración VEX: el producto incluye la corrección.", null, null, now, _maxAcceptanceDays);
                return true;
            case VexStatus.NotAffected or VexStatus.Fixed:
                return false;
            default:
                if (finding.Status != FindingStatus.NotAffected)
                {
                    return false;
                }

                finding.ChangeStatus(FindingStatus.New, StatusChangeSource.Vex, Finding.SystemActor,
                    statement is null ? "La declaración VEX fue revocada." : $"Nueva declaración VEX con estado {statement.Status}.",
                    null, null, now, _maxAcceptanceDays);
                return true;
        }
    }

    private async Task<int> AddNewAlertsAsync(List<Alert> pending, CancellationToken cancellationToken)
    {
        if (pending.Count == 0)
        {
            return 0;
        }

        var existingKeys = await alerts.ExistingKeysAsync(pending.Select(a => a.DedupKey).ToList(), cancellationToken);
        var added = 0;
        foreach (var alert in pending.Where(a => existingKeys.Add(a.DedupKey)))
        {
            alerts.Add(alert);
            added++;
        }

        return added;
    }

    private static IEnumerable<Alert> AlertsForNewFinding(Project project, Finding finding, Vulnerability vulnerability, Component component)
    {
        var now = finding.FirstDetectedAt;
        var label = $"{vulnerability.CveId ?? vulnerability.ExternalId} en {component.Name}@{component.Version} ({project.Name})";
        if (finding.PriorityLevel == PriorityLevel.P1)
        {
            yield return new Alert(project.Id, finding.Id, AlertType.NewP1, $"Nuevo hallazgo P1: {label}", $"NEW_P1:{finding.Id}", now);
        }

        if (vulnerability.InKev)
        {
            yield return new Alert(project.Id, finding.Id, AlertType.NewKevMatch, $"Vulnerabilidad del catálogo KEV detectada: {label}", $"NEW_KEV_MATCH:{finding.Id}", now);
        }

        if (finding.ForensicTriageRequired)
        {
            yield return new Alert(project.Id, finding.Id, AlertType.ForensicTriage, $"BOD 26-04 exige triage forense: {label}", $"FORENSIC_TRIAGE:{finding.Id}", now);
        }
    }

    private static PriorityInputs BuildPriorityInputs(Project project, Vulnerability vulnerability, KevEntry? kevEntry, ComponentVulnerability match) =>
        new(
            vulnerability.InKev,
            kevEntry?.DateAdded,
            kevEntry?.KnownRansomwareCampaignUse ?? false,
            vulnerability.SsvcExploitation,
            vulnerability.EpssScore,
            vulnerability.EpssPercentile,
            vulnerability.Severity,
            vulnerability.CvssScore,
            project.Exposure,
            match.FixAvailable,
            match.SuggestedFixVersion);

    private static SlaInputs BuildSlaInputs(Project project, Vulnerability vulnerability, KevEntry? kevEntry, Finding finding) =>
        new(
            project.Exposure,
            vulnerability.InKev,
            kevEntry?.DateAdded,
            vulnerability.SsvcAutomatable,
            vulnerability.SsvcTechnicalImpact,
            vulnerability.CvssVector,
            vulnerability.Severity,
            finding.FirstDetectedAt);

    private static PriorityExplanationDto ToExplanation(
        PriorityRuleVersion rule, PriorityRuleSet ruleSet, PriorityDecision decision, Vulnerability vulnerability, Project project, ComponentVulnerability match) =>
        new(
            rule.Version,
            decision.MatchedRuleId,
            decision.Level,
            new PriorityInputsDto(
                decision.Exploitation,
                decision.ExploitationSources,
                vulnerability.EpssPercentile,
                ruleSet.EpssPercentileThreshold,
                vulnerability.Severity,
                vulnerability.CvssScore,
                vulnerability.CvssVersion,
                decision.Impact,
                project.Exposure,
                match.FixAvailable,
                match.SuggestedFixVersion),
            decision.Reasons);

    private static SlaExplanationDto ToExplanation(SlaDecision sla, Project project, Vulnerability vulnerability) =>
        new(
            sla.Policy,
            sla.Row,
            sla.Days,
            sla.StartedAt,
            sla.StartBasis,
            sla.DueAt,
            sla.ForensicTriageRequired,
            project.Exposure == Exposure.Public,
            vulnerability.InKev,
            sla.Ssvc?.Automatable,
            sla.Ssvc?.AutomatableSource,
            sla.Ssvc?.TechnicalImpact,
            sla.Ssvc?.TechnicalImpactSource,
            vulnerability.Severity);

    [LoggerMessage(Level = LogLevel.Information, Message = "Project {ProjectId} reconciled: created={Created} reopened={Reopened} closed={Closed} vex={Vex} priority={Priority} sla={Sla} alerts={Alerts}")]
    private static partial void LogReconciled(ILogger logger, Guid projectId, int created, int reopened, int closed, int vex, int priority, int sla, int alerts);
}
