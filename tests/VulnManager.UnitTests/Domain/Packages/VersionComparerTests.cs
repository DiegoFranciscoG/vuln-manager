using VulnManager.Domain.Packages;

namespace VulnManager.UnitTests.Domain.Packages;

public class VersionComparerTests
{
    [Theory]
    [InlineData("2.14.1", "2.15.0", -1)]
    [InlineData("4.17.15", "4.17.21", -1)]
    [InlineData("1.10.0", "1.9.9", 1)]
    [InlineData("1.0", "1.0.0", 0)]
    [InlineData("v1.2.3", "1.2.3", 0)]
    [InlineData("1.0.0-rc1", "1.0.0", -1)]
    [InlineData("1.0.0-alpha", "1.0.0-beta", -1)]
    [InlineData("1.0.0-beta", "1.0.0-rc.1", -1)]
    [InlineData("2.0-beta9", "2.0", -1)]
    [InlineData("1.0.0+build.5", "1.0.0", 0)]
    [InlineData("5.3.18", "5.3.18", 0)]
    public void Compare_orders_common_version_schemes(string left, string right, int expected)
    {
        Math.Sign(VersionComparer.Instance.Compare(left, right)).Should().Be(expected);
        Math.Sign(VersionComparer.Instance.Compare(right, left)).Should().Be(-expected);
    }

    [Fact]
    public void LowestGreaterThan_picks_the_fix_for_the_installed_branch()
    {
        // log4j-core 2.14.1 is affected by GHSA-jfh8-c2jp-5v3q, whose OSV ranges end at 2.3.1, 2.12.2 and 2.15.0.
        var fix = VersionComparer.Instance.LowestGreaterThan("2.14.1", ["2.3.1", "2.12.2", "2.15.0"]);

        fix.Should().Be("2.15.0");
    }

    [Fact]
    public void LowestGreaterThan_returns_null_when_no_newer_fix_exists()
    {
        VersionComparer.Instance.LowestGreaterThan("3.0.0", ["2.15.0"]).Should().BeNull();
    }
}
