using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Packages;
using VulnManager.IntegrationTests.Infrastructure;

namespace VulnManager.IntegrationTests;

public class SyncTests(PostgresContainer postgres, ExternalApisStub apis) : IntegrationTestBase(postgres, apis)
{
    /// <summary>Acceptance: synchronization is idempotent (second run updates nothing and leaves identical data).</summary>
    [Fact]
    public async Task Second_full_sync_changes_nothing()
    {
        await ProjectWithLog4jFindingsAsync();
        var before = await SnapshotAsync();

        var runs = await SyncAsync();

        runs.Should().HaveCount(5);
        runs.Should().OnlyContain(r => r.ItemsUpdated == 0);
        runs.Single(r => r.Source == SyncSource.Kev).Status.Should().Be(SyncRunStatus.Skipped, "the KEV feed answers 304 to the conditional GET");
        (await SnapshotAsync()).Should().Be(before);
    }

    [Fact]
    public async Task Kev_second_run_sends_the_stored_validators()
    {
        await ProjectWithLog4jFindingsAsync();
        Apis.Server.ResetLogEntries();

        await SyncAsync(SyncSource.Kev);

        var request = Apis.Server.LogEntries.Single(e => e.RequestMessage!.Path == "/kev.json").RequestMessage!;
        request.Headers!["If-Modified-Since"].Single().Should().Be(ExternalApisStub.KevLastModified);
        request.Headers["If-None-Match"].Single().Should().Be(ExternalApisStub.KevETag);
    }

    [Fact]
    public async Task Sync_runs_record_http_counters()
    {
        await ProjectWithLog4jFindingsAsync();

        var runs = await Factory.WithDbAsync(db => db.SyncRuns.AsNoTracking().OrderBy(r => r.StartedAt).ToListAsync(Ct));

        runs.Single(r => r.Source == SyncSource.Osv && r.Trigger == SyncTrigger.Manual).HttpRequests.Should().Be(4, "2 querybatch (batch size 1) + 2 vulnerability details");
        runs.Single(r => r.Source == SyncSource.Kev).Watermark.Should().Contain("2026.09.25");
        runs.Single(r => r.Source == SyncSource.Epss).Watermark.Should().Be("2026-09-26");
        runs.Should().OnlyContain(r => r.HttpThrottled == 0);
    }

    [Fact]
    public async Task External_trigger_requires_the_shared_token()
    {
        using var anonymous = Factory.CreateClient();

        var missing = await anonymous.PostAsync("/api/sync/trigger", null, Ct);
        var wrong = new HttpRequestMessage(HttpMethod.Post, "/api/sync/trigger");
        wrong.Headers.Add("X-Sync-Token", "not-the-token");
        var right = new HttpRequestMessage(HttpMethod.Post, "/api/sync/trigger");
        right.Headers.Add("X-Sync-Token", Factory.SyncToken);

        missing.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await anonymous.SendAsync(wrong, Ct)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await anonymous.SendAsync(right, Ct)).StatusCode.Should().Be(HttpStatusCode.Accepted);
    }

    private Task<string> SnapshotAsync() => Factory.WithDbAsync(async db =>
    {
        var findings = await db.Findings.AsNoTracking().OrderBy(f => f.Id)
            .Select(f => new { f.Id, f.Status, f.PriorityLevel, f.PriorityExplanation, f.SlaDueAt, f.SlaExplanation, f.UpdatedAt })
            .ToListAsync(Ct);
        var vulnerabilities = await db.Vulnerabilities.AsNoTracking().OrderBy(v => v.Id)
            .Select(v => new { v.Id, v.ModifiedAt, v.CvssScore, v.EpssScore, v.InKev, v.SsvcAutomatable })
            .ToListAsync(Ct);
        var counts = new
        {
            history = await db.FindingStatusHistory.CountAsync(Ct),
            alerts = await db.Alerts.CountAsync(Ct),
            matches = await db.ComponentVulnerabilities.CountAsync(Ct),
            kev = await db.KevEntries.CountAsync(Ct),
        };
        return System.Text.Json.JsonSerializer.Serialize(new { findings, vulnerabilities, counts });
    });
}

/// <summary>Acceptance: the NVD client never exceeds the published rolling-window limit (scaled down to keep the test fast).</summary>
public class NvdRateLimitTests(PostgresContainer postgres, ExternalApisStub apis) : IntegrationTestBase(postgres, apis)
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan Spacing = TimeSpan.FromMilliseconds(250);

    protected override void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.UseSetting("ExternalSources:NvdWindowSeconds", "2");
        builder.UseSetting("ExternalSources:NvdMinSpacingSeconds", "0.25");
    }

    [Fact]
    public async Task Nvd_job_respects_five_requests_per_rolling_window_and_spacing()
    {
        await SeedCvesWithoutCvssAsync(12);
        Apis.Server.ResetLogEntries();

        var run = (await SyncAsync(SyncSource.Nvd)).Single();

        run.HttpRequests.Should().Be(12);
        run.ItemsUpdated.Should().Be(12, "every CVE received the NVD primary CVSS");
        var times = Apis.RequestTimes("/rest/json/cves/2.0");
        times.Should().HaveCount(12);
        foreach (var start in times)
        {
            times.Count(t => t >= start && t < start + Window - TimeSpan.FromMilliseconds(50)).Should().BeLessThanOrEqualTo(5);
        }

        times.Zip(times.Skip(1)).Should().OnlyContain(p => p.Second - p.First >= Spacing - TimeSpan.FromMilliseconds(50));
        (times[^1] - times[0]).Should().BeGreaterThan(Window * 2, "12 requests need at least 3 windows of 5");
    }

    private Task SeedCvesWithoutCvssAsync(int count) => Factory.WithDbAsync(async db =>
    {
        var now = DateTimeOffset.UtcNow;
        var component = new Component(PackageUrl.Parse("pkg:npm/rate-limit-probe@1.0.0"), now);
        db.Components.Add(component);
        for (var i = 0; i < count; i++)
        {
            var vulnerability = new Vulnerability($"GHSA-test-{i:0000}", now);
            vulnerability.ApplyOsvRecord(now, now, null, [$"CVE-2099-{1000 + i}"], "probe", null, null, Domain.Scoring.Severity.Unknown, now);
            db.Vulnerabilities.Add(vulnerability);
            db.ComponentVulnerabilities.Add(new ComponentVulnerability(component.Id, vulnerability.Id, [], null, now));
        }

        await db.SaveChangesAsync(Ct);
    });
}
