using VulnManager.Domain.Common;
using VulnManager.Domain.Packages;
using VulnManager.Domain.Vex;

namespace VulnManager.Domain.Entities;

public enum VexSource
{
    Manual = 0,
    CycloneDxVex = 1,
}

/// <summary>VEX statement for a project (the "product" in CISA terms). Statements are revoked, never deleted.</summary>
public sealed class VexStatement
{
    private VexStatement()
    {
    }

    public VexStatement(
        Guid projectId,
        VexStatementDraft draft,
        VexSource source,
        Guid? sourceImportId,
        string? cdxState,
        IReadOnlyCollection<string>? cdxResponse,
        string author,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(draft);
        var errors = VexStatementRules.Validate(draft);
        if (errors.Count > 0)
        {
            throw new DomainException(string.Join(" ", errors));
        }

        Id = Guid.CreateVersion7(now);
        ProjectId = projectId;
        VulnerabilityRef = draft.VulnerabilityRef.Trim();
        ComponentPurl = draft.ComponentPurl is null ? null : NormalizePurl(draft.ComponentPurl);
        Status = draft.Status;
        JustificationScheme = draft.Justification is null ? null : draft.JustificationScheme;
        Justification = draft.Justification;
        ImpactStatement = string.IsNullOrWhiteSpace(draft.ImpactStatement) ? null : draft.ImpactStatement.Trim();
        ActionStatement = string.IsNullOrWhiteSpace(draft.ActionStatement) ? null : draft.ActionStatement.Trim();
        Source = source;
        SourceImportId = sourceImportId;
        CdxState = cdxState;
        CdxResponse = cdxResponse?.ToArray();
        Author = author;
        CreatedAt = now;
    }

    public Guid Id { get; private set; }

    public Guid ProjectId { get; private set; }

    public string VulnerabilityRef { get; private set; } = string.Empty;

    public string? ComponentPurl { get; private set; }

    public VexStatus Status { get; private set; }

    public VexJustificationScheme? JustificationScheme { get; private set; }

    public string? Justification { get; private set; }

    public string? ImpactStatement { get; private set; }

    public string? ActionStatement { get; private set; }

    public string? CdxState { get; private set; }

    public string[]? CdxResponse { get; private set; }

    public VexSource Source { get; private set; }

    public Guid? SourceImportId { get; private set; }

    public string Author { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public string? RevokedBy { get; private set; }

    public VexCandidate ToCandidate() => new(Id, VulnerabilityRef, ComponentPurl, Status, CreatedAt, RevokedAt is not null);

    public void Revoke(string actor, DateTimeOffset now)
    {
        if (RevokedAt is not null)
        {
            throw new DomainException("La declaración VEX ya estaba revocada.");
        }

        RevokedAt = now;
        RevokedBy = actor;
    }

    private static string NormalizePurl(string purl)
    {
        var parsed = PackageUrl.Parse(purl);
        return parsed.Version is null ? parsed.VersionlessCoordinates : parsed.Coordinates;
    }
}
