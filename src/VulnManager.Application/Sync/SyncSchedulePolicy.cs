using VulnManager.Application.Options;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Sync;

/// <summary>Decides which sources are due, honouring each provider's published cadence.</summary>
public static class SyncSchedulePolicy
{
    /// <summary>EPSS scores are published daily a few minutes after 13:30 UTC (FIRST EPSS FAQ).</summary>
    public static readonly TimeOnly EpssPublicationUtc = new(13, 45);

    public static IReadOnlyList<SyncSource> DueSources(DateTimeOffset now, IReadOnlyDictionary<SyncSource, DateTimeOffset?> lastSuccess, SyncOptions options)
    {
        ArgumentNullException.ThrowIfNull(lastSuccess);
        ArgumentNullException.ThrowIfNull(options);
        var due = new List<SyncSource>();
        foreach (var source in SyncRunner.FullOrder)
        {
            var last = lastSuccess.GetValueOrDefault(source);
            var isDue = source switch
            {
                SyncSource.Kev => IsOlderThan(last, now, TimeSpan.FromHours(options.KevIntervalHours)),
                SyncSource.Osv => IsOlderThan(last, now, TimeSpan.FromHours(options.OsvRecheckHours)),
                SyncSource.Cve => IsOlderThan(last, now, TimeSpan.FromDays(1)),
                SyncSource.Nvd => IsOlderThan(last, now, TimeSpan.FromDays(1)),
                SyncSource.Epss => IsEpssDue(last, now, options),
                _ => false,
            };
            if (isDue)
            {
                due.Add(source);
            }
        }

        return due;
    }

    private static bool IsOlderThan(DateTimeOffset? last, DateTimeOffset now, TimeSpan interval) => last is null || now - last.Value >= interval;

    private static bool IsEpssDue(DateTimeOffset? last, DateTimeOffset now, SyncOptions options)
    {
        if (last is null)
        {
            return true;
        }

        var todaysPublication = new DateTimeOffset(DateOnly.FromDateTime(now.UtcDateTime).ToDateTime(EpssPublicationUtc), TimeSpan.Zero);
        var latestPublication = now >= todaysPublication ? todaysPublication : todaysPublication.AddDays(-1);
        return last.Value < latestPublication && now - last.Value >= TimeSpan.FromHours(Math.Min(options.EpssIntervalHours, 20));
    }
}
