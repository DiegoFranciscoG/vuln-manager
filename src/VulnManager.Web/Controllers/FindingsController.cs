using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Security;
using VulnManager.Application.Services;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Web.Security;

namespace VulnManager.Web.Controllers;

public sealed class FindingFilter
{
    public Guid? ProjectId { get; set; }

    public FindingStatus[]? Status { get; set; }

    public PriorityLevel[]? Priority { get; set; }

    public Severity[]? Severity { get; set; }

    public bool? InKev { get; set; }

    public bool? Overdue { get; set; }

    public bool? FixAvailable { get; set; }

    [System.ComponentModel.DataAnnotations.StringLength(100)]
    public string? Search { get; set; }

    [System.ComponentModel.DataAnnotations.Range(1, 10_000)]
    public int Page { get; set; } = 1;

    [System.ComponentModel.DataAnnotations.Range(1, 200)]
    public int PageSize { get; set; } = 25;

    public FindingSort Sort { get; set; } = FindingSort.Priority;

    public FindingQuery ToQuery() => new()
    {
        ProjectId = ProjectId,
        Statuses = Status,
        Priorities = Priority,
        Severities = Severity,
        InKev = InKev,
        Overdue = Overdue,
        FixAvailable = FixAvailable,
        Search = Search,
        Page = Page,
        PageSize = PageSize,
        Sort = Sort,
    };
}

[ApiController]
[Route("api/findings")]
[Produces("application/json")]
public sealed class FindingsController(FindingService findings) : ControllerBase
{
    /// <summary>Filters, sorts (priority by default: level, KEV, EPSS, CVSS, fix, SLA) and paginates findings.</summary>
    [HttpGet]
    public Task<PagedResult<FindingListItemDto>> Query([FromQuery] FindingFilter filter, CancellationToken cancellationToken) =>
        findings.QueryAsync(User.ToActor(), filter.ToQuery(), cancellationToken);

    /// <summary>Finding detail with the priority and SLA explanation and the status history.</summary>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<FindingDetailDto> Get(Guid id, CancellationToken cancellationToken) => findings.GetAsync(User.ToActor(), id, cancellationToken);

    /// <summary>Triage: ACCEPTED (needs riskAcceptedUntil), MITIGATED, FALSE_POSITIVE or back to NEW. Justification is mandatory.</summary>
    [HttpPost("{id:guid}/status")]
    [Authorize(Policy = AppPolicies.CanTriage)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public Task<FindingDetailDto> ChangeStatus(Guid id, [FromBody] ChangeFindingStatusRequest request, CancellationToken cancellationToken) =>
        findings.ChangeStatusAsync(User.ToActor(), id, request, cancellationToken);

    /// <summary>CSV export of the filtered findings (protected against formula injection).</summary>
    [HttpGet("export.csv")]
    [Produces("text/csv")]
    public async Task<IActionResult> Export([FromQuery] FindingFilter filter, CancellationToken cancellationToken)
    {
        var csv = await findings.ExportCsvAsync(User.ToActor(), filter.ToQuery(), cancellationToken);
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(csv)).ToArray(), "text/csv; charset=utf-8", "hallazgos.csv");
    }
}
