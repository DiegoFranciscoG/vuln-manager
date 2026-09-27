using System.Collections.Concurrent;
using System.Net;
using VulnManager.Application.Abstractions.External;

namespace VulnManager.Infrastructure.Http;

/// <summary>Process-wide counters of outbound requests and throttled responses per named client.</summary>
public sealed class HttpCallStats : IHttpCallStats
{
    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);

    public (int Requests, int Throttled) Snapshot(string clientName)
    {
        var counter = _counters.GetOrAdd(clientName, _ => new Counter());
        return (Volatile.Read(ref counter.Requests), Volatile.Read(ref counter.Throttled));
    }

    internal void Record(string clientName, bool throttled)
    {
        var counter = _counters.GetOrAdd(clientName, _ => new Counter());
        Interlocked.Increment(ref counter.Requests);
        if (throttled)
        {
            Interlocked.Increment(ref counter.Throttled);
        }
    }

    private sealed class Counter
    {
        public int Requests;
        public int Throttled;
    }
}

/// <summary>Counts every attempt; 429 (and 403 for NVD, which answers rate-limit violations with 403) counts as throttled.</summary>
public sealed class HttpStatsHandler(HttpCallStats stats, string clientName, bool forbiddenMeansThrottled) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            var throttled = response.StatusCode == HttpStatusCode.TooManyRequests
                            || (forbiddenMeansThrottled && response.StatusCode == HttpStatusCode.Forbidden);
            stats.Record(clientName, throttled);
            return response;
        }
        catch (HttpRequestException)
        {
            stats.Record(clientName, throttled: false);
            throw;
        }
    }
}
