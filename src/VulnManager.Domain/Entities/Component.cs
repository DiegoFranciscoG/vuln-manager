using VulnManager.Domain.Packages;

namespace VulnManager.Domain.Entities;

/// <summary>Global component catalog, identified by the canonical purl coordinates (with version, without qualifiers).</summary>
public sealed class Component
{
    private Component()
    {
    }

    public Component(PackageUrl purl, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(purl);
        Id = Guid.CreateVersion7(now);
        Purl = purl.Coordinates;
        Type = purl.Type;
        Namespace = purl.Namespace;
        Name = purl.Name;
        Version = purl.Version ?? throw new ArgumentException("A component needs a version to be matched.", nameof(purl));
        CreatedAt = now;
    }

    public Guid Id { get; private set; }

    public string Purl { get; private set; } = string.Empty;

    public string Type { get; private set; } = string.Empty;

    public string? Namespace { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string Version { get; private set; } = string.Empty;

    public DateTimeOffset? VulnsCheckedAt { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public void MarkChecked(DateTimeOffset now) => VulnsCheckedAt = now;
}

/// <summary>Result of the OSV match between a component and a vulnerability.</summary>
public sealed class ComponentVulnerability
{
    private ComponentVulnerability()
    {
    }

    public ComponentVulnerability(Guid componentId, Guid vulnerabilityId, IReadOnlyCollection<string> fixedVersions, string? suggestedFixVersion, DateTimeOffset now)
    {
        ComponentId = componentId;
        VulnerabilityId = vulnerabilityId;
        FirstMatchedAt = now;
        Refresh(fixedVersions, suggestedFixVersion, now);
    }

    public Guid ComponentId { get; private set; }

    public Guid VulnerabilityId { get; private set; }

    public string[] FixedVersions { get; private set; } = [];

    public bool FixAvailable { get; private set; }

    public string? SuggestedFixVersion { get; private set; }

    public DateTimeOffset FirstMatchedAt { get; private set; }

    public DateTimeOffset LastMatchedAt { get; private set; }

    /// <summary>Returns true when stored data changed (used to count real updates for idempotency checks).</summary>
    public bool Refresh(IReadOnlyCollection<string> fixedVersions, string? suggestedFixVersion, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(fixedVersions);
        var sorted = fixedVersions.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var changed = !sorted.SequenceEqual(FixedVersions) || suggestedFixVersion != SuggestedFixVersion;
        FixedVersions = sorted;
        FixAvailable = sorted.Length > 0;
        SuggestedFixVersion = suggestedFixVersion;
        LastMatchedAt = now;
        return changed;
    }
}
