using Microsoft.Extensions.Options;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Exceptions;
using VulnManager.Application.Options;
using VulnManager.Domain.Common;
using VulnManager.Domain.Findings;

namespace VulnManager.Application.Services;

public sealed class FindingService(
    IFindingRepository findings,
    IUnitOfWork unitOfWork,
    AuditService audit,
    TimeProvider time,
    IOptions<FindingOptions> options)
{
    public Task<PagedResult<FindingListItemDto>> QueryAsync(Actor actor, FindingQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(query);
        ScopeQuery(actor, query);
        return findings.QueryAsync(query, time.GetUtcNow(), cancellationToken);
    }

    public async Task<FindingDetailDto> GetAsync(Actor actor, Guid id, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var detail = await findings.GetDetailAsync(id, time.GetUtcNow(), cancellationToken);
        if (detail is null || !actor.CanAccessProject(detail.Summary.ProjectId))
        {
            throw NotFoundException.For("Hallazgo", id);
        }

        return detail;
    }

    public async Task<FindingDetailDto> ChangeStatusAsync(Actor actor, Guid id, ChangeFindingStatusRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(request);
        if (!actor.CanTriage)
        {
            throw new ForbiddenException("Se requiere rol Analyst o Admin para cambiar el estado.");
        }

        var finding = await findings.GetAsync(id, includeHistory: false, cancellationToken);
        if (finding is null || !actor.CanAccessProject(finding.ProjectId))
        {
            throw NotFoundException.For("Hallazgo", id);
        }

        if (request.Status == FindingStatus.NotAffected)
        {
            throw new InvalidInputException("Para marcar NOT_AFFECTED registra una declaración VEX con su justificación.");
        }

        var from = finding.Status;
        try
        {
            finding.ChangeStatus(request.Status, StatusChangeSource.User, actor.Id, request.Justification, request.RiskAcceptedUntil, null,
                time.GetUtcNow(), options.Value.RiskAcceptanceMaxDays);
        }
        catch (DomainException ex)
        {
            throw new InvalidInputException(ex.Message, ex);
        }

        audit.Record(actor, AuditActions.FindingStatusChanged, "finding", finding.Id, new { from, to = request.Status, request.RiskAcceptedUntil });
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return await GetAsync(actor, id, cancellationToken);
    }

    public async Task<string> ExportCsvAsync(Actor actor, FindingQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(query);
        ScopeQuery(actor, query);
        var rows = await findings.ExportAsync(query, time.GetUtcNow(), options.Value.CsvMaxRows, cancellationToken);
        return CsvWriter.Write(rows);
    }

    private static void ScopeQuery(Actor actor, FindingQuery query)
    {
        if (actor.ProjectScope is { } scope)
        {
            if (query.ProjectId is not null && query.ProjectId != scope)
            {
                throw NotFoundException.For("Proyecto", query.ProjectId);
            }

            query.ProjectId = scope;
        }
    }
}
