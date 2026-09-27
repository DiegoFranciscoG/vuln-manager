using VulnManager.Application.Abstractions.External;
using VulnManager.Domain.Packages;

namespace VulnManager.Application.Sync;

/// <summary>
/// Extracts "fixed" events for the component's package from the OSV "affected" entries and suggests the fix for the
/// installed branch: the first fixed version of a range whose introduced version is at or below the current one.
/// </summary>
public static class FixedVersionResolver
{
    public static (IReadOnlyList<string> FixedVersions, string? Suggested) Resolve(IReadOnlyList<OsvAffected> affected, PackageUrl component)
    {
        ArgumentNullException.ThrowIfNull(affected);
        ArgumentNullException.ThrowIfNull(component);
        var current = component.Version;
        var target = component.VersionlessCoordinates;
        var comparer = VersionComparer.Instance;

        var ranges = affected
            .Where(a => a.Purl is not null && PackageUrl.TryParse(a.Purl, out var p) && p.VersionlessCoordinates == target)
            .SelectMany(a => a.Ranges)
            .Where(r => r.Type is "SEMVER" or "ECOSYSTEM")
            .ToList();

        var allFixed = ranges.SelectMany(r => r.Events).Select(e => e.Fixed).OfType<string>().Distinct(StringComparer.Ordinal).ToList();
        if (current is null || allFixed.Count == 0)
        {
            return (allFixed, null);
        }

        var candidates = new List<string>();
        foreach (var range in ranges)
        {
            string? introduced = null;
            foreach (var evt in range.Events)
            {
                if (evt.Introduced is not null)
                {
                    introduced = evt.Introduced;
                }
                else if (evt.Fixed is not null && introduced is not null)
                {
                    var covers = (introduced == "0" || comparer.Compare(introduced, current) <= 0) && comparer.Compare(current, evt.Fixed) < 0;
                    if (covers)
                    {
                        candidates.Add(evt.Fixed);
                    }

                    introduced = null;
                }
            }
        }

        var suggested = candidates.Count > 0
            ? candidates.Order(comparer).First()
            : comparer.LowestGreaterThan(current, allFixed);
        return (allFixed, suggested);
    }
}
