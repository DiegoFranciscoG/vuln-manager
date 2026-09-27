using System.Globalization;

namespace VulnManager.Domain.Packages;

/// <summary>
/// Best-effort, ecosystem-neutral version ordering (semver-like). Numeric segments compare numerically,
/// pre-release markers (alpha, beta, rc, snapshot...) sort before the release. Used only to suggest a fixed version;
/// "fix available" itself relies on OSV "fixed" events.
/// </summary>
public sealed class VersionComparer : IComparer<string>
{
    public static readonly VersionComparer Instance = new();

    private static readonly string[] PreReleaseOrder = ["dev", "snapshot", "alpha", "a", "beta", "b", "milestone", "m", "preview", "pre", "rc", "cr"];

    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y))
        {
            return 0;
        }

        if (x is null)
        {
            return -1;
        }

        if (y is null)
        {
            return 1;
        }

        var left = Tokenize(x);
        var right = Tokenize(y);
        var length = Math.Max(left.Count, right.Count);
        for (var i = 0; i < length; i++)
        {
            var result = CompareTokens(i < left.Count ? left[i] : null, i < right.Count ? right[i] : null);
            if (result != 0)
            {
                return result;
            }
        }

        return 0;
    }

    /// <summary>Returns the lowest candidate strictly greater than <paramref name="current"/>, or null.</summary>
    public string? LowestGreaterThan(string current, IEnumerable<string> candidates) =>
        candidates.Where(c => Compare(c, current) > 0).Order(this).FirstOrDefault();

    private static int CompareTokens(Token? left, Token? right)
    {
        if (left is null && right is null)
        {
            return 0;
        }

        if (left is null)
        {
            return -CompareWithMissing(right!);
        }

        if (right is null)
        {
            return CompareWithMissing(left);
        }

        if (left.IsNumeric && right.IsNumeric)
        {
            return left.Number.CompareTo(right.Number);
        }

        if (left.IsNumeric != right.IsNumeric)
        {
            return left.IsNumeric ? 1 : -1;
        }

        var rank = QualifierRank(left.Text).CompareTo(QualifierRank(right.Text));
        return rank != 0 ? rank : string.Compare(left.Text, right.Text, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Compares an existing token against a missing one (1.0 vs 1.0.1, 1.0-rc1 vs 1.0).</summary>
    private static int CompareWithMissing(Token token)
    {
        if (token.IsNumeric)
        {
            return token.Number == 0 ? 0 : 1;
        }

        return QualifierRank(token.Text) < PreReleaseOrder.Length ? -1 : 1;
    }

    private static int QualifierRank(string text)
    {
        var lower = text.ToLowerInvariant();
        if (lower is "final" or "ga" or "release")
        {
            return PreReleaseOrder.Length;
        }

        var index = Array.IndexOf(PreReleaseOrder, lower);
        return index >= 0 ? index : PreReleaseOrder.Length + 1;
    }

    private static List<Token> Tokenize(string version)
    {
        var tokens = new List<Token>();
        var trimmed = version.Trim().TrimStart('v', 'V');
        var plus = trimmed.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0)
        {
            trimmed = trimmed[..plus];
        }

        foreach (var part in trimmed.Split(['.', '-', '_'], StringSplitOptions.RemoveEmptyEntries))
        {
            var start = 0;
            for (var i = 1; i <= part.Length; i++)
            {
                if (i == part.Length || char.IsAsciiDigit(part[i]) != char.IsAsciiDigit(part[i - 1]))
                {
                    tokens.Add(Token.From(part[start..i]));
                    start = i;
                }
            }
        }

        return tokens;
    }

    private sealed record Token(string Text, bool IsNumeric, long Number)
    {
        public static Token From(string text) =>
            long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
                ? new Token(text, true, number)
                : new Token(text, false, 0);
    }
}
