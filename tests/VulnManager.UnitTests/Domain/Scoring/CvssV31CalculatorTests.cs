using VulnManager.Domain.Scoring;

namespace VulnManager.UnitTests.Domain.Scoring;

public class CvssV31CalculatorTests
{
    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0)] // CVE-2021-44228 (NVD 10.0)
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)] // CVE-2022-22965 (NVD 9.8)
    [InlineData("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0)] // CVE-2021-45046 (NVD 9.0): Critical boundary
    [InlineData("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9)] // CVE-2021-45105 (NVD 5.9)
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5)] // CVE-2023-44487
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8)]
    [InlineData("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4)] // scope changed uses PR:L = 0.68
    [InlineData("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 6.5)]
    [InlineData("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L", 5.1)] // scope changed uses PR:H = 0.5
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)] // impact <= 0
    public void BaseScore_matches_the_FIRST_formula_and_NVD_published_scores(string vector, double expected)
    {
        var score = CvssV31Calculator.BaseScore(CvssV3Vector.Parse(vector));

        score.Should().Be((decimal)expected);
    }

    [Fact]
    public void BaseScore_ignores_temporal_metrics_published_by_OSV()
    {
        var withTemporal = CvssV3Vector.Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H");

        CvssV31Calculator.BaseScore(withTemporal).Should().Be(10.0m);
    }

    [Fact]
    public void BaseScore_accepts_CVSS_3_0_vectors()
    {
        var vector = CvssV3Vector.Parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

        vector.Version.Should().Be("3.0");
        CvssV31Calculator.BaseScore(vector).Should().Be(9.8m);
    }

    [Theory]
    [InlineData(4.02, 4.1)]
    [InlineData(4.0, 4.0)]
    [InlineData(4.000000000000001, 4.0)] // floating point noise must not round up
    [InlineData(0.30000000000000004, 0.3)]
    [InlineData(9.99, 10.0)]
    public void Roundup_follows_appendix_A(double input, double expected)
    {
        CvssV31Calculator.Roundup(input).Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")] // missing prefix
    [InlineData("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")] // missing A
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L")] // duplicated metric
    [InlineData("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")] // invalid value
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:H")] // unknown metric
    public void TryParse_rejects_malformed_vectors(string? vector)
    {
        CvssV3Vector.TryParse(vector, out var parsed).Should().BeFalse();
        parsed.Should().BeNull();
    }
}
