using System.Text.Json;
using VulnManager.Application.Dtos;
using VulnManager.Application.Options;
using VulnManager.Application.Services;
using VulnManager.Application.Sync;
using VulnManager.Domain.Entities;
using VulnManager.Domain.Findings;
using VulnManager.Domain.Packages;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;
using VulnManager.Infrastructure.External;
using VulnManager.UnitTests.TestSupport;

namespace VulnManager.UnitTests.Application;

public class CsvWriterTests
{
    [Theory]
    [InlineData("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\"")]
    [InlineData("+1", "\"'+1\"")]
    [InlineData("-1", "\"'-1\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("\tcmd", "\"'\tcmd\"")]
    [InlineData("normal", "\"normal\"")]
    [InlineData("con \"comillas\"", "\"con \"\"comillas\"\"\"")]
    [InlineData(null, "\"\"")]
    public void Escape_neutralizes_formula_injection_and_quotes(string? value, string expected)
    {
        CsvWriter.Escape(value).Should().Be(expected);
    }

    [Fact]
    public void Write_emits_header_and_one_line_per_finding()
    {
        var row = new FindingListItemDto(Guid.Empty, Guid.Empty, "=cmd|' /C calc'!A0", "pkg:npm/a@1.0.0", "a", "1.0.0", "GHSA-x", "CVE-2021-44228", null,
            Severity.Critical, 10.0m, 0.9m, 0.99m, true, true, FindingStatus.FalsePositive, PriorityLevel.P1, true, "2.15.0",
            new DateTimeOffset(2021, 12, 13, 0, 0, 0, TimeSpan.Zero), -1000, true, true, new DateTimeOffset(2026, 9, 26, 0, 0, 0, TimeSpan.Zero));

        var lines = CsvWriter.Write([row]).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        lines.Should().HaveCount(2);
        lines[0].Should().StartWith("\"finding_id\",\"project\"");
        lines[1].Should().Contain("\"'=cmd|' /C calc'!A0\"").And.Contain("\"FALSE_POSITIVE\"").And.Contain("\"CRITICAL\"").And.Contain("\"2021-12-13T00:00:00Z\"");
    }
}

public class SbomFileNameTests
{
    [Theory]
    [InlineData("bom.cdx.json", "bom.cdx.json")]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("C:\\builds\\app\\bom.json", "bom.json")]
    [InlineData("<script>alert(1)</script>.json", "script.json")] // "/" is treated as a path separator
    [InlineData("...", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void SanitizeFileName_keeps_only_a_safe_file_name(string? input, string? expected)
    {
        SbomImportService.SanitizeFileName(input).Should().Be(expected);
    }
}

public class FixedVersionResolverTests
{
    private static IReadOnlyList<VulnManager.Application.Abstractions.External.OsvAffected> Log4ShellAffected()
    {
        using var document = JsonDocument.Parse(Fixtures.Read("osv/GHSA-jfh8-c2jp-5v3q.json"));
        return OsvClient.Parse(document.RootElement)!.Affected;
    }

    [Theory]
    [InlineData("2.14.1", "2.15.0")]
    [InlineData("2.10.0", "2.12.2")]
    [InlineData("2.0-beta9", "2.3.1")]
    public void Suggests_the_fix_of_the_installed_branch(string installed, string expected)
    {
        var (fixedVersions, suggested) = FixedVersionResolver.Resolve(Log4ShellAffected(), PackageUrl.Parse($"pkg:maven/org.apache.logging.log4j/log4j-core@{installed}"));

        fixedVersions.Should().Contain(["2.3.1", "2.12.2", "2.15.0"]);
        suggested.Should().Be(expected);
    }

    [Fact]
    public void Ignores_ranges_of_other_packages()
    {
        var (fixedVersions, suggested) = FixedVersionResolver.Resolve(Log4ShellAffected(), PackageUrl.Parse("pkg:maven/org.ops4j.pax.logging/pax-logging-log4j2@1.10.3"));

        fixedVersions.Should().Contain("1.10.8").And.NotContain("2.15.0");
        suggested.Should().Be("1.10.8");
    }

    [Fact]
    public void Returns_nothing_for_an_unrelated_package()
    {
        FixedVersionResolver.Resolve(Log4ShellAffected(), PackageUrl.Parse("pkg:npm/left-pad@1.3.0")).FixedVersions.Should().BeEmpty();
    }
}

public class SyncSchedulePolicyTests
{
    private static readonly SyncOptions Options = new();

    private static IReadOnlyList<SyncSource> Due(DateTimeOffset now, Dictionary<SyncSource, DateTimeOffset?> last) =>
        SyncSchedulePolicy.DueSources(now, last, Options);

    [Fact]
    public void Everything_is_due_on_the_first_run()
    {
        Due(DateTimeOffset.UtcNow, []).Should().Equal(SyncRunner.FullOrder);
    }

    [Theory]
    [InlineData(5, false)]
    [InlineData(6, true)]
    public void KEV_is_refreshed_every_6_hours(int hoursAgo, bool due)
    {
        var now = new DateTimeOffset(2026, 9, 26, 20, 0, 0, TimeSpan.Zero);
        var last = SyncRunner.FullOrder.ToDictionary(s => s, _ => (DateTimeOffset?)now.AddMinutes(-1));
        last[SyncSource.Kev] = now.AddHours(-hoursAgo);

        Due(now, last).Contains(SyncSource.Kev).Should().Be(due);
    }

    [Theory]
    [InlineData(13, 30, false)] // today's scores are not published yet
    [InlineData(14, 0, true)] // after the ~13:30 UTC publication
    public void EPSS_waits_for_the_daily_publication(int hour, int minute, bool due)
    {
        var now = new DateTimeOffset(2026, 9, 26, hour, minute, 0, TimeSpan.Zero);
        var last = SyncRunner.FullOrder.ToDictionary(s => s, _ => (DateTimeOffset?)now.AddMinutes(-1));
        last[SyncSource.Epss] = new DateTimeOffset(2026, 9, 25, 14, 0, 0, TimeSpan.Zero);

        Due(now, last).Contains(SyncSource.Epss).Should().Be(due);
    }
}
