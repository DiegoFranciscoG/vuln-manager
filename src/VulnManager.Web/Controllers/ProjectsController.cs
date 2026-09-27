using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using VulnManager.Application.Dtos;
using VulnManager.Application.Security;
using VulnManager.Application.Services;
using VulnManager.Domain.Entities;
using VulnManager.Web.Security;

namespace VulnManager.Web.Controllers;

[ApiController]
[Route("api/projects")]
[Produces("application/json")]
public sealed class ProjectsController(ProjectService projects, ApiKeyService apiKeys, SbomImportService sboms, VexService vex) : ControllerBase
{
    /// <summary>Lists projects with finding counters (an API key only sees its own project).</summary>
    [HttpGet]
    public Task<IReadOnlyList<ProjectSummaryDto>> List([FromQuery] bool includeArchived = false, CancellationToken cancellationToken = default) =>
        projects.ListAsync(User.ToActor(), includeArchived, cancellationToken);

    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public Task<ProjectDto> Get(Guid id, CancellationToken cancellationToken) => projects.GetAsync(User.ToActor(), id, cancellationToken);

    [HttpPost]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType<ProjectDto>(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Create([FromBody] ProjectRequest request, CancellationToken cancellationToken)
    {
        var created = await projects.CreateAsync(User.ToActor(), request, cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = created.Id }, created);
    }

    /// <summary>Updates a project. Changing the exposure recalculates BOD 26-04 deadlines.</summary>
    [HttpPut("{id:guid}")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    public Task<ProjectDto> Update(Guid id, [FromBody] ProjectRequest request, CancellationToken cancellationToken) =>
        projects.UpdateAsync(User.ToActor(), id, request, cancellationToken);

    /// <summary>Archives a project (logical delete; history is kept).</summary>
    [HttpDelete("{id:guid}")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Archive(Guid id, CancellationToken cancellationToken)
    {
        await projects.ArchiveAsync(User.ToActor(), id, cancellationToken);
        return NoContent();
    }

    [HttpGet("{id:guid}/api-keys")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    public Task<IReadOnlyList<ApiKeyDto>> ListKeys(Guid id, CancellationToken cancellationToken) => apiKeys.ListAsync(User.ToActor(), id, cancellationToken);

    /// <summary>Creates an ingestion key for CI pipelines. The secret is shown only in this response.</summary>
    [HttpPost("{id:guid}/api-keys")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType<ApiKeyCreatedDto>(StatusCodes.Status201Created)]
    public async Task<IActionResult> CreateKey(Guid id, [FromBody] CreateApiKeyRequest request, CancellationToken cancellationToken)
    {
        var created = await apiKeys.CreateAsync(User.ToActor(), id, request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    [HttpDelete("{id:guid}/api-keys/{keyId:guid}")]
    [Authorize(Policy = AppPolicies.CanAdminister)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeKey(Guid id, Guid keyId, CancellationToken cancellationToken)
    {
        await apiKeys.RevokeAsync(User.ToActor(), id, keyId, cancellationToken);
        return NoContent();
    }

    /// <summary>
    /// Imports a CycloneDX JSON SBOM (1.4-1.7), max 10 MiB: multipart field "file" or a raw body with Content-Type
    /// application/vnd.cyclonedx+json. Re-sending the same file returns 200 with the existing import (idempotent).
    /// </summary>
    [HttpPost("{id:guid}/sboms")]
    [Authorize(Policy = AppPolicies.CanIngest)]
    [EnableRateLimiting(RateLimitPolicies.Ingest)]
    [RequestSizeLimit(SbomImport.MaxSizeBytes + (64 * 1024))]
    [RequestFormLimits(MultipartBodyLengthLimit = SbomImport.MaxSizeBytes + (64 * 1024))]
    [Consumes("multipart/form-data", "application/vnd.cyclonedx+json", "application/json")]
    [ProducesResponseType<SbomImportResultDto>(StatusCodes.Status201Created)]
    [ProducesResponseType<SbomImportResultDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ImportSbom(Guid id, [FromQuery] string? sourceRef, CancellationToken cancellationToken)
    {
        var (content, fileName, error) = await RequestBody.ReadAsync(Request, SbomImport.MaxSizeBytes, cancellationToken);
        if (error is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "Solicitud inválida", detail: error);
        }

        var actor = User.ToActor();
        var source = actor.Type == ActorType.ApiKey ? SbomSource.Api : SbomSource.Upload;
        var result = await sboms.ImportAsync(actor, id, content, fileName, source, sourceRef, cancellationToken);
        return result.Created ? StatusCode(StatusCodes.Status201Created, result) : Ok(result);
    }

    [HttpGet("{id:guid}/sboms")]
    public Task<IReadOnlyList<SbomImportDto>> ListSboms(Guid id, [FromQuery] int take = 20, CancellationToken cancellationToken = default) =>
        sboms.ListAsync(User.ToActor(), id, take, cancellationToken);

    [HttpGet("{id:guid}/vex-statements")]
    public Task<IReadOnlyList<VexStatementDto>> ListVex(Guid id, [FromQuery] bool includeRevoked = false, CancellationToken cancellationToken = default) =>
        vex.ListAsync(User.ToActor(), id, includeRevoked, cancellationToken);

    /// <summary>Records a VEX statement (CISA vocabulary). "not_affected" needs a justification or an impact statement.</summary>
    [HttpPost("{id:guid}/vex-statements")]
    [Authorize(Policy = AppPolicies.CanTriage)]
    [ProducesResponseType<VexStatementDto>(StatusCodes.Status201Created)]
    public async Task<IActionResult> CreateVex(Guid id, [FromBody] CreateVexStatementRequest request, CancellationToken cancellationToken)
    {
        var created = await vex.CreateAsync(User.ToActor(), id, request, cancellationToken);
        return StatusCode(StatusCodes.Status201Created, created);
    }

    [HttpDelete("{id:guid}/vex-statements/{statementId:guid}")]
    [Authorize(Policy = AppPolicies.CanTriage)]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> RevokeVex(Guid id, Guid statementId, CancellationToken cancellationToken)
    {
        await vex.RevokeAsync(User.ToActor(), id, statementId, cancellationToken);
        return NoContent();
    }

    /// <summary>Imports a CycloneDX VEX document (vulnerabilities[].analysis).</summary>
    [HttpPost("{id:guid}/vex")]
    [Authorize(Policy = AppPolicies.CanTriage)]
    [EnableRateLimiting(RateLimitPolicies.Ingest)]
    [RequestSizeLimit(SbomImport.MaxSizeBytes + (64 * 1024))]
    [RequestFormLimits(MultipartBodyLengthLimit = SbomImport.MaxSizeBytes + (64 * 1024))]
    [Consumes("multipart/form-data", "application/vnd.cyclonedx+json", "application/json")]
    public async Task<IActionResult> ImportVex(Guid id, CancellationToken cancellationToken)
    {
        var (content, _, error) = await RequestBody.ReadAsync(Request, SbomImport.MaxSizeBytes, cancellationToken);
        if (error is not null)
        {
            return Problem(statusCode: StatusCodes.Status400BadRequest, title: "Solicitud inválida", detail: error);
        }

        var created = await vex.ImportCycloneDxAsync(User.ToActor(), id, System.Text.Encoding.UTF8.GetString(content.Span), cancellationToken);
        return Ok(new { statementsCreated = created });
    }
}
