using VulnManager.Application.Abstractions.External;

namespace VulnManager.Application.Sync;

/// <summary>
/// OSV can return several records for the same flaw (for example GHSA-... and PYSEC-... both aliasing one CVE).
/// Records that share an id or alias are grouped and one representative is kept (GHSA first, then CVE, then the rest),
/// so one flaw produces one finding.
/// </summary>
public static class AliasDeduplicator
{
    public static IReadOnlyList<OsvVulnerability> Representatives(IReadOnlyList<OsvVulnerability> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var parent = records.Select((_, i) => i).ToArray();
        var owner = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < records.Count; i++)
        {
            foreach (var key in records[i].Aliases.Append(records[i].Id))
            {
                if (owner.TryGetValue(key, out var other))
                {
                    Union(parent, i, other);
                }
                else
                {
                    owner[key] = i;
                }
            }
        }

        return records
            .Select((record, index) => (Record: record, Group: Find(parent, index)))
            .GroupBy(x => x.Group)
            .Select(g => g.Select(x => x.Record).OrderBy(Rank).ThenBy(r => r.Id, StringComparer.Ordinal).First())
            .ToList();
    }

    private static int Rank(OsvVulnerability record) =>
        record.Id.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase) ? 0
        : record.Id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) ? 1
        : 2;

    private static int Find(int[] parent, int i)
    {
        while (parent[i] != i)
        {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }

        return i;
    }

    private static void Union(int[] parent, int a, int b)
    {
        var rootA = Find(parent, a);
        var rootB = Find(parent, b);
        if (rootA != rootB)
        {
            parent[Math.Max(rootA, rootB)] = Math.Min(rootA, rootB);
        }
    }
}
