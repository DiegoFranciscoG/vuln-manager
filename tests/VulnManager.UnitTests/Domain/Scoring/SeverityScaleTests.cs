using VulnManager.Domain.Scoring;

namespace VulnManager.UnitTests.Domain.Scoring;

public class SeverityScaleTests
{
    [Theory]
    [InlineData(0.0, Severity.None)]
    [InlineData(0.1, Severity.Low)]
    [InlineData(3.9, Severity.Low)]
    [InlineData(4.0, Severity.Medium)]
    [InlineData(6.9, Severity.Medium)]
    [InlineData(7.0, Severity.High)]
    [InlineData(8.9, Severity.High)]
    [InlineData(9.0, Severity.Critical)]
    [InlineData(10.0, Severity.Critical)]
    public void FromScore_uses_the_qualitative_scale_boundaries(double score, Severity expected)
    {
        SeverityScale.FromScore((decimal)score).Should().Be(expected);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(10.1)]
    public void FromScore_rejects_out_of_range_scores(double score)
    {
        var act = () => SeverityScale.FromScore((decimal)score);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Theory]
    [InlineData("CRITICAL", Severity.Critical)]
    [InlineData("high", Severity.High)]
    [InlineData("MODERATE", Severity.Medium)]
    [InlineData("Medium", Severity.Medium)]
    [InlineData("LOW", Severity.Low)]
    [InlineData("", Severity.Unknown)]
    [InlineData(null, Severity.Unknown)]
    [InlineData("important", Severity.Unknown)]
    public void FromText_maps_advisory_database_labels(string? text, Severity expected)
    {
        SeverityScale.FromText(text).Should().Be(expected);
    }
}
