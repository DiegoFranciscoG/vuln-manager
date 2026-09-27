using VulnManager.Domain.Packages;

namespace VulnManager.Domain.Vex;

/// <summary>Minimal view of a stored VEX statement used for matching.</summary>
public sealed record VexCandidate(Guid Id, string VulnerabilityRef, string? ComponentPurl, VexStatus Status, DateTimeOffset CreatedAt, bool Revoked);

/// <summary>
/// Picks the VEX statement that applies to a finding: same vulnerability (id or alias), component scope matching
/// (exact version, any version, or the whole project), not revoked. Most specific wins, then the most recent.
/// </summary>
public static class VexMatcher
{
    public static VexCandidate? SelectApplicable(IEnumerable<VexCandidate> candidates, string vulnerabilityId, IEnumerable<string> aliases, PackageUrl component)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(component);

        var ids = new HashSet<string>(aliases ?? [], StringComparer.OrdinalIgnoreCase) { vulnerabilityId };

        return candidates
            .Where(c => !c.Revoked && ids.Contains(c.VulnerabilityRef.Trim()))
            .Select(c => (Candidate: c, Specificity: Specificity(c.ComponentPurl, component)))
            .Where(x => x.Specificity > 0)
            .OrderByDescending(x => x.Specificity)
            .ThenByDescending(x => x.Candidate.CreatedAt)
            .Select(x => x.Candidate)
            .FirstOrDefault();
    }

    /// <summary>3 = exact version, 2 = every version of the package, 1 = whole project, 0 = not applicable.</summary>
    private static int Specificity(string? statementPurl, PackageUrl component)
    {
        if (statementPurl is null)
        {
            return 1;
        }

        if (!PackageUrl.TryParse(statementPurl, out var parsed))
        {
            return 0;
        }

        if (parsed.Version is null)
        {
            return string.Equals(parsed.VersionlessCoordinates, component.VersionlessCoordinates, StringComparison.Ordinal) ? 2 : 0;
        }

        return string.Equals(parsed.Coordinates, component.Coordinates, StringComparison.Ordinal) ? 3 : 0;
    }
}
