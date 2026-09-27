namespace VulnManager.Infrastructure.Http;

/// <summary>
/// Client-side limiter for providers that publish a rolling-window quota (NVD: 5 requests per rolling 30 s without key,
/// 50 with key, plus a recommended pause between requests). Callers are served one at a time; the clock is injected so
/// the behaviour is testable with a fake time provider.
/// </summary>
public sealed class RollingWindowRateLimiter : IDisposable
{
    private readonly int _permitLimit;
    private readonly TimeSpan _window;
    private readonly TimeSpan _minSpacing;
    private readonly TimeProvider _time;
    private readonly Queue<DateTimeOffset> _grants = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTimeOffset? _lastGrant;

    public RollingWindowRateLimiter(int permitLimit, TimeSpan window, TimeSpan minSpacing, TimeProvider time)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(permitLimit, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(minSpacing, TimeSpan.Zero);
        _permitLimit = permitLimit;
        _window = window;
        _minSpacing = minSpacing;
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public int PermitLimit => _permitLimit;

    public TimeSpan Window => _window;

    public TimeSpan MinSpacing => _minSpacing;

    public async Task WaitAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                var now = _time.GetUtcNow();
                while (_grants.Count > 0 && now - _grants.Peek() >= _window)
                {
                    _grants.Dequeue();
                }

                var windowWait = _grants.Count < _permitLimit ? TimeSpan.Zero : _window - (now - _grants.Peek());
                var spacingWait = _lastGrant is { } last && now - last < _minSpacing ? _minSpacing - (now - last) : TimeSpan.Zero;
                var wait = windowWait > spacingWait ? windowWait : spacingWait;
                if (wait <= TimeSpan.Zero)
                {
                    _grants.Enqueue(now);
                    _lastGrant = now;
                    return;
                }

                await Task.Delay(wait, _time, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}

/// <summary>Applies a <see cref="RollingWindowRateLimiter"/> to every attempt (retries included).</summary>
public sealed class RateLimitingHandler(RollingWindowRateLimiter limiter) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
