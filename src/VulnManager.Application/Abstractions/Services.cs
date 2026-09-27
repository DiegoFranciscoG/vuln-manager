using VulnManager.Domain.Entities;

namespace VulnManager.Application.Abstractions;

public sealed record SyncRequest(SyncSource? Source, SyncTrigger Trigger, Guid? ProjectId = null);

/// <summary>Hands synchronization requests to the background worker (non-blocking).</summary>
public interface ISyncDispatcher
{
    bool TryEnqueue(SyncRequest request);
}

/// <summary>Delivers alerts outside the app (HTTPS webhook). SMTP is not used: Render free blocks ports 25/465/587.</summary>
public interface IAlertNotifier
{
    bool IsEnabled { get; }

    Task<bool> NotifyAsync(Alert alert, string projectName, CancellationToken cancellationToken = default);
}

public sealed record ParsedComponent(string Purl, string? BomRef, string? Scope);

public sealed record ParsedVexEntry(
    string VulnerabilityId,
    string State,
    string? Justification,
    IReadOnlyList<string> Responses,
    string? Detail,
    IReadOnlyList<string> AffectsRefs);

public sealed record ParsedBom(
    string SpecVersion,
    string? SerialNumber,
    int? Version,
    IReadOnlyList<ParsedComponent> Components,
    int SkippedComponents,
    IReadOnlyList<ParsedVexEntry> Vex);

/// <summary>Validates a CycloneDX JSON document against the official schema and extracts components and VEX analysis.</summary>
public interface ICycloneDxParser
{
    ParsedBom Parse(string json);
}
