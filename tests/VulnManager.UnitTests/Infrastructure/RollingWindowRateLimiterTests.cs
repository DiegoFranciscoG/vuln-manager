using Microsoft.Extensions.Time.Testing;
using VulnManager.Infrastructure.Http;

namespace VulnManager.UnitTests.Infrastructure;

/// <summary>Acceptance criterion: synchronization respects the published API limits (NVD: 5 requests per rolling 30 s, 6 s apart).</summary>
public class RollingWindowRateLimiterTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 26, 12, 0, 0, TimeSpan.Zero);

    private static async Task<List<DateTimeOffset>> AcquireAsync(RollingWindowRateLimiter limiter, FakeTimeProvider time, int count)
    {
        var grants = new List<DateTimeOffset>();
        for (var i = 0; i < count; i++)
        {
            var pending = limiter.WaitAsync(CancellationToken.None);
            var guard = 0;
            while (!pending.IsCompleted)
            {
                time.Advance(TimeSpan.FromMilliseconds(250));
                await Task.Delay(1, TestContext.Current.CancellationToken);
                guard.Should().BeLessThan(10_000, "the limiter must eventually grant a permit");
                guard++;
            }

            await pending;
            grants.Add(time.GetUtcNow());
        }

        return grants;
    }

    [Fact]
    public async Task NVD_public_limit_never_allows_more_than_5_requests_in_any_rolling_30_seconds()
    {
        var time = new FakeTimeProvider(Start);
        using var limiter = new RollingWindowRateLimiter(5, TimeSpan.FromSeconds(30), TimeSpan.Zero, time);

        var grants = await AcquireAsync(limiter, time, 16);

        foreach (var grant in grants)
        {
            grants.Count(g => g >= grant && g < grant + TimeSpan.FromSeconds(30)).Should().BeLessThanOrEqualTo(5);
        }

        grants[5].Should().BeOnOrAfter(grants[0] + TimeSpan.FromSeconds(30), "the 6th request must wait for the window to roll");
    }

    [Fact]
    public async Task NVD_recommended_pause_keeps_requests_at_least_6_seconds_apart()
    {
        var time = new FakeTimeProvider(Start);
        using var limiter = new RollingWindowRateLimiter(5, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(6), time);

        var grants = await AcquireAsync(limiter, time, 8);

        grants.Zip(grants.Skip(1)).Should().OnlyContain(pair => pair.Second - pair.First >= TimeSpan.FromSeconds(6));
    }

    [Fact]
    public async Task With_API_key_the_window_allows_50_requests()
    {
        var time = new FakeTimeProvider(Start);
        using var limiter = new RollingWindowRateLimiter(50, TimeSpan.FromSeconds(30), TimeSpan.Zero, time);

        var grants = await AcquireAsync(limiter, time, 51);

        grants.Take(50).Should().OnlyContain(g => g == Start, "50 permits are available immediately");
        grants[50].Should().BeOnOrAfter(Start + TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task Waiting_honours_cancellation()
    {
        var time = new FakeTimeProvider(Start);
        using var limiter = new RollingWindowRateLimiter(1, TimeSpan.FromSeconds(30), TimeSpan.Zero, time);
        await limiter.WaitAsync(CancellationToken.None);
        using var cts = new CancellationTokenSource();

        var pending = limiter.WaitAsync(cts.Token);
        await cts.CancelAsync();

        await pending.Invoking(async p => await p).Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData(0, 30, 0)]
    [InlineData(5, 0, 0)]
    [InlineData(5, 30, -1)]
    public void Invalid_configuration_is_rejected(int permits, int windowSeconds, int spacingSeconds)
    {
        var act = () => new RollingWindowRateLimiter(permits, TimeSpan.FromSeconds(windowSeconds), TimeSpan.FromSeconds(spacingSeconds), TimeProvider.System);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }
}
