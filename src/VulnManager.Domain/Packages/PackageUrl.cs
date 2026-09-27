using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace VulnManager.Domain.Packages;

/// <summary>
/// Package URL (purl, ECMA-427): <c>pkg:type/namespace/name@version?qualifiers#subpath</c>.
/// Component identity uses <see cref="Coordinates"/> (type, namespace, name and version, without qualifiers or subpath),
/// so the same package produced by two SBOM tools maps to a single component.
/// </summary>
public sealed class PackageUrl : IEquatable<PackageUrl>
{
    private static readonly HashSet<string> LowercaseNameTypes = ["npm", "pypi", "github", "bitbucket", "composer"];

    private PackageUrl(string type, string? @namespace, string name, string? version, IReadOnlyDictionary<string, string> qualifiers, string? subpath)
    {
        Type = type;
        Namespace = @namespace;
        Name = name;
        Version = version;
        Qualifiers = qualifiers;
        Subpath = subpath;
    }

    public string Type { get; }

    public string? Namespace { get; }

    public string Name { get; }

    public string? Version { get; }

    public IReadOnlyDictionary<string, string> Qualifiers { get; }

    public string? Subpath { get; }

    /// <summary>Canonical purl without qualifiers and subpath. Used as the component identity and to query OSV.</summary>
    public string Coordinates => Build(includeVersion: true, includeExtras: false);

    /// <summary>Canonical purl without version, qualifiers and subpath: identifies every version of a package.</summary>
    public string VersionlessCoordinates => Build(includeVersion: false, includeExtras: false);

    public static PackageUrl Parse(string value) =>
        TryParse(value, out var purl) ? purl : throw new FormatException($"Invalid package URL: '{value}'.");

    public static bool TryParse(string? value, [NotNullWhen(true)] out PackageUrl? purl)
    {
        purl = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2000)
        {
            return false;
        }

        var remainder = value.Trim();

        string? subpath = null;
        var hash = remainder.IndexOf('#', StringComparison.Ordinal);
        if (hash >= 0)
        {
            subpath = NormalizeSubpath(remainder[(hash + 1)..]);
            remainder = remainder[..hash];
        }

        var qualifiers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var question = remainder.IndexOf('?', StringComparison.Ordinal);
        if (question >= 0)
        {
            if (!TryParseQualifiers(remainder[(question + 1)..], qualifiers))
            {
                return false;
            }

            remainder = remainder[..question];
        }

        if (!remainder.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        remainder = remainder[4..].Trim('/');
        var slash = remainder.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0)
        {
            return false;
        }

        var type = remainder[..slash].ToLowerInvariant();
        if (!type.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '+' or '-') || char.IsAsciiDigit(type[0]))
        {
            return false;
        }

        remainder = remainder[(slash + 1)..].Trim('/');

        string? version = null;
        var lastSlash = remainder.LastIndexOf('/');
        var at = remainder.LastIndexOf('@');
        if (at > lastSlash && at >= 0)
        {
            version = Decode(remainder[(at + 1)..]);
            remainder = remainder[..at];
            if (string.IsNullOrEmpty(version))
            {
                version = null;
            }
        }

        var segments = remainder.Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Decode).ToList();
        if (segments.Count == 0 || segments.Any(string.IsNullOrWhiteSpace))
        {
            return false;
        }

        var name = segments[^1];
        var @namespace = segments.Count > 1 ? string.Join('/', segments.Take(segments.Count - 1)) : null;

        if (LowercaseNameTypes.Contains(type))
        {
            name = name.ToLowerInvariant();
            @namespace = @namespace?.ToLowerInvariant();
        }

        if (type == "pypi")
        {
            name = name.Replace('_', '-');
        }

        purl = new PackageUrl(type, @namespace, name, version, qualifiers, subpath);
        return true;
    }

    public PackageUrl WithoutVersion() => new(Type, Namespace, Name, null, Qualifiers, Subpath);

    public bool Equals(PackageUrl? other) => other is not null && string.Equals(ToString(), other.ToString(), StringComparison.Ordinal);

    public override bool Equals(object? obj) => Equals(obj as PackageUrl);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(ToString());

    /// <summary>Full canonical form: lowercase type, sorted qualifiers and percent-encoded segments.</summary>
    public override string ToString() => Build(includeVersion: true, includeExtras: true);

    private string Build(bool includeVersion, bool includeExtras)
    {
        var builder = new StringBuilder("pkg:").Append(Type).Append('/');
        if (Namespace is not null)
        {
            builder.AppendJoin('/', Namespace.Split('/').Select(Encode)).Append('/');
        }

        builder.Append(Encode(Name));
        if (includeVersion && Version is not null)
        {
            builder.Append('@').Append(Encode(Version));
        }

        if (includeExtras && Qualifiers.Count > 0)
        {
            builder.Append('?').AppendJoin('&', Qualifiers.Select(q => $"{q.Key}={Encode(q.Value)}"));
        }

        if (includeExtras && Subpath is not null)
        {
            builder.Append('#').Append(Subpath);
        }

        return builder.ToString();
    }

    private static bool TryParseQualifiers(string raw, SortedDictionary<string, string> qualifiers)
    {
        foreach (var pair in raw.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = pair.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                return false;
            }

            var key = pair[..equals].ToLowerInvariant();
            var val = Decode(pair[(equals + 1)..]);
            if (val.Length == 0)
            {
                continue;
            }

            if (!qualifiers.TryAdd(key, val))
            {
                return false;
            }
        }

        return true;
    }

    private static string? NormalizeSubpath(string raw)
    {
        var segments = raw.Split('/', StringSplitOptions.RemoveEmptyEntries).Where(s => s is not "." and not "..").ToArray();
        return segments.Length == 0 ? null : string.Join('/', segments);
    }

    private static string Decode(string value) => Uri.UnescapeDataString(value);

    private static string Encode(string value) =>
        Uri.EscapeDataString(value).Replace("%3A", ":", StringComparison.Ordinal);
}
