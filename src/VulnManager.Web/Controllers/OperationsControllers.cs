using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Common;
using VulnManager.Application.Dtos;
using VulnManager.Application.Security;
using VulnManager.Application.Services;
using VulnManager.Domain.Entities;
using VulnManager.Web.Security;

namespace VulnManager.Web.Controllers;

[ApiController]
[Route("api/priority-rules")]
[Produces("application/json")]
public sealed class PriorityRulesController(PriorityRuleService rules) : ControllerBase
{
    [HttpGet]
    public Task<IReadOnlyList<PriorityRuleDto>> List(CancellationToken cancellationToken) => rules.ListAsync(cancellationToken);

    /// <summary>Active decision table and SLA policy.</summary>
    [HttpGet("active")]
    public Task<PriorityRuleDto> Active(CancellationToken cancellationToken) => rules.GetActiveAsync(cancellationToken);

    /// <summary>Creates a new immutable version. It must cover the 12 signal combinations and have no unreachable rules.</summary>
    [HttpPost]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType<PriorityRuleDto>(StatusCodes.Status201Created)]
    public async Task<IActionResult> Create([FromBody] CreatePriorityRuleRequest request, CancellationToken cancellationToken)
    {
        var created = await rules.CreateAsync(User.ToActor(), request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    /// <summary>Activates a version and recalculates priority and SLA of every finding.</summary>
    [HttpPost("{id:guid}/activate")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    public Task<ReconciliationResult> Activate(Guid id, CancellationToken cancellationToken) => rules.ActivateAsync(User.ToActor(), id, cancellationToken);
}

[ApiController]
[Route("api/alerts")]
[Produces("application/json")]
public sealed class AlertsController(AlertService alerts) : ControllerBase
{
    [HttpGet]
    public Task<PagedResult<AlertDto>> List([FromQuery] Guid? projectId, [FromQuery] bool onlyOpen = true, [FromQuery] int page = 1, [FromQuery] int pageSize = 25, CancellationToken cancellationToken = default) =>
        alerts.ListAsync(User.ToActor(), projectId, onlyOpen, page, pageSize, cancellationToken);

    [HttpPost("{id:guid}/ack")]
    [Authorize(Policy = AppPolicies.CanTriage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Acknowledge(Guid id, CancellationToken cancellationToken)
    {
        await alerts.AcknowledgeAsync(User.ToActor(), id, cancellationToken);
        return NoContent();
    }
}

public sealed class SyncRequestBody
{
    /// <summary>OSV, KEV, EPSS, CVE or NVD; empty runs every source in order.</summary>
    public SyncSource? Source { get; set; }
}

public sealed class SyncTriggerOptions
{
    public const string Section = "Sync";

    /// <summary>Shared secret for the GitHub Actions cron (X-Sync-Token header). Empty disables the endpoint.</summary>
    public string? TriggerToken { get; set; }
}

[ApiController]
[Route("api/sync")]
[Produces("application/json")]
public sealed class SyncController(ISyncDispatcher dispatcher, DashboardService dashboard, AuditService audit, Microsoft.Extensions.Options.IOptions<SyncTriggerOptions> options) : ControllerBase
{
    [HttpGet("runs")]
    public Task<IReadOnlyList<SyncRunDto>> Runs([FromQuery] int take = 50, CancellationToken cancellationToken = default) =>
        dashboard.RecentSyncRunsAsync(take, cancellationToken);

    /// <summary>Queues a synchronization (Admin). Progress is visible in GET /api/sync/runs.</summary>
    [HttpPost]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> Run([FromBody] SyncRequestBody body, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (!dispatcher.TryEnqueue(new SyncRequest(body.Source, SyncTrigger.Manual)))
        {
            return Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Cola llena", detail: "Hay demasiadas sincronizaciones pendientes.");
        }

        await audit.RecordNowAsync(User.ToActor(), AuditActions.SyncTriggered, "sync", body.Source?.ToString() ?? "ALL", cancellationToken: cancellationToken);
        return Accepted();
    }

    /// <summary>
    /// Wake-up endpoint for the scheduled GitHub Actions workflow (Render free instances sleep after 15 minutes).
    /// Requires the X-Sync-Token secret; compared in constant time and rate limited.
    /// </summary>
    [HttpPost("trigger")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitPolicies.SyncTrigger)]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Trigger([FromHeader(Name = "X-Sync-Token")] string? token)
    {
        var expected = options.Value.TriggerToken;
        if (string.IsNullOrWhiteSpace(expected) || expected.Length < 32)
        {
            return NotFound();
        }

        if (token is null || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), SHA256.HashData(Encoding.UTF8.GetBytes(expected))))
        {
            return Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Token inválido");
        }

        dispatcher.TryEnqueue(new SyncRequest(null, SyncTrigger.External));
        return Accepted();
    }
}

[ApiController]
[Route("api")]
[Produces("application/json")]
public sealed class DashboardController(DashboardService dashboard, AuditService audit) : ControllerBase
{
    [HttpGet("dashboard")]
    public Task<DashboardDto> Get(CancellationToken cancellationToken) => dashboard.GetAsync(User.ToActor(), cancellationToken);

    /// <summary>Audit trail (Admin). Entries contain actor ids, never e-mails or secrets.</summary>
    [HttpGet("audit")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    public Task<PagedResult<AuditEntryDto>> Audit([FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken cancellationToken = default) =>
        audit.ListAsync(User.ToActor(), page, pageSize, cancellationToken);
}
