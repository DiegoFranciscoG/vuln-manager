using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Mappers;
using VulnManager.Domain.Common;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Sla;

namespace VulnManager.Application.Services;

/// <summary>Rule versions are immutable: a change creates a new version; activating it recalculates every finding.</summary>
public sealed class PriorityRuleService(
    IPriorityRuleRepository rules,
    IUnitOfWork unitOfWork,
    AuditService audit,
    FindingReconciliationService reconciliation,
    TimeProvider time)
{
    public async Task<PriorityRuleDto> GetActiveAsync(CancellationToken cancellationToken = default) =>
        (await rules.GetActiveAsync(cancellationToken) ?? throw new NotFoundException("No hay una regla de prioridad activa.")).ToDto();

    public async Task<IReadOnlyList<PriorityRuleDto>> ListAsync(CancellationToken cancellationToken = default) =>
        (await rules.ListAsync(cancellationToken)).Select(r => r.ToDto()).ToList();

    /// <summary>Validates a candidate rule set without saving it (used by the UI preview).</summary>
    public static IReadOnlyList<string> Validate(CreatePriorityRuleRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return PriorityRuleSetValidator.Validate(ToRuleSet(request));
    }

    public async Task<PriorityRuleDto> CreateAsync(Actor actor, CreatePriorityRuleRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        EnsureAdmin(actor);

        var sla = new SlaSettings(request.SlaPolicy, request.SlaSeverityDays ?? new Dictionary<Domain.Scoring.Severity, int>(SlaSettings.DefaultSeverityDays), request.FixOnUpgradeDays);
        PriorityRuleVersion version;
        try
        {
            version = new PriorityRuleVersion(await rules.MaxVersionAsync(cancellationToken) + 1, request.Name, request.Notes, ToRuleSet(request), sla, actor.Id, time.GetUtcNow());
        }
        catch (DomainException ex)
        {
            throw new InvalidInputException(ex.Message, ex);
        }

        rules.Add(version);
        audit.Record(actor, AuditActions.RuleCreated, "priority_rule", version.Id, new { version.Version, version.Name });
        await unitOfWork.SaveChangesAsync(cancellationToken);

        if (request.Activate)
        {
            await ActivateAsync(actor, version.Id, cancellationToken);
        }

        return version.ToDto();
    }

    public async Task<ReconciliationResult> ActivateAsync(Actor actor, Guid id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        EnsureAdmin(actor);
        var target = await rules.GetAsync(id, cancellationToken) ?? throw NotFoundException.For("Regla", id);
        if (target.IsActive)
        {
            return ReconciliationResult.Empty;
        }

        var current = await rules.GetActiveAsync(cancellationToken);
        if (current is not null)
        {
            // Deactivate first: the partial unique index allows only one active version at any time.
            current.Deactivate();
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }

        target.Activate();
        audit.Record(actor, AuditActions.RuleActivated, "priority_rule", target.Id, new { target.Version, previous = current?.Version });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return await reconciliation.ReconcileAllAsync(cancellationToken);
    }

    private static PriorityRuleSet ToRuleSet(CreatePriorityRuleRequest request) =>
        new(request.EpssPercentileThreshold, request.HighImpactMinCvss, request.UnknownSeverityAs, request.SsvcActiveCountsAsExploited, request.Rules);

    private static void EnsureAdmin(Actor actor)
    {
        if (!actor.IsAdmin)
        {
            throw new ForbiddenException("Solo un administrador puede gestionar las reglas de prioridad.");
        }
    }
}
