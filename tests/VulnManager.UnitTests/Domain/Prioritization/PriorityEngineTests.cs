using VulnManager.Domain.Common;
using VulnManager.Domain.Prioritization;
using VulnManager.Domain.Scoring;

namespace VulnManager.UnitTests.Domain.Prioritization;

public class PriorityEngineTests
{
    private static readonly PriorityRuleSet Rules = PriorityRuleSet.Default;

    private static PriorityInputs Inputs(
        bool inKev = false,
        SsvcExploitation? ssvc = null,
        decimal? epssPercentile = null,
        decimal? cvss = null,
        Severity severity = Severity.Unknown,
        Exposure exposure = Exposure.Internal,
        bool fixAvailable = false,
        string? fix = null) =>
        new(inKev, inKev ? new DateOnly(2021, 12, 10) : null, false, ssvc, epssPercentile, epssPercentile, severity, cvss, exposure, fixAvailable, fix);

    public static TheoryData<bool, decimal?, decimal, Exposure, PriorityLevel, string> DefaultTable => new()
    {
        // inKev, epss percentile, cvss, exposure, level, rule
        { true, null, 9.8m, Exposure.Public, PriorityLevel.P1, "R1" },
        { true, null, 9.8m, Exposure.Internal, PriorityLevel.P1, "R2" },
        { true, null, 5.0m, Exposure.Public, PriorityLevel.P1, "R1" },
        { true, null, 5.0m, Exposure.Internal, PriorityLevel.P2, "R3" },
        { false, 0.95m, 9.8m, Exposure.Public, PriorityLevel.P2, "R4" },
        { false, 0.95m, 9.8m, Exposure.Internal, PriorityLevel.P2, "R4" },
        { false, 0.95m, 5.0m, Exposure.Public, PriorityLevel.P3, "R5" },
        { false, 0.95m, 5.0m, Exposure.Internal, PriorityLevel.P3, "R5" },
        { false, 0.10m, 9.8m, Exposure.Public, PriorityLevel.P3, "R6" },
        { false, 0.10m, 9.8m, Exposure.Internal, PriorityLevel.P4, "R7" },
        { false, 0.10m, 5.0m, Exposure.Public, PriorityLevel.P4, "R7" },
        { false, 0.10m, 5.0m, Exposure.Internal, PriorityLevel.P4, "R7" },
    };

    [Theory]
    [MemberData(nameof(DefaultTable))]
    public void Default_table_covers_the_12_signal_combinations(bool inKev, decimal? epss, decimal cvss, Exposure exposure, PriorityLevel level, string rule)
    {
        var decision = PriorityEngine.Evaluate(Rules, Inputs(inKev: inKev, epssPercentile: epss, cvss: cvss, exposure: exposure));

        decision.Level.Should().Be(level);
        decision.MatchedRuleId.Should().Be(rule);
    }

    [Fact]
    public void KEV_wins_regardless_of_a_zero_EPSS_score()
    {
        var decision = PriorityEngine.Evaluate(Rules, Inputs(inKev: true, epssPercentile: 0.0m, cvss: 4.3m, exposure: Exposure.Public));

        decision.Exploitation.Should().Be(ExploitationSignal.Active);
        decision.ExploitationSources.Should().Equal("KEV");
        decision.Level.Should().Be(PriorityLevel.P1);
    }

    [Fact]
    public void SSVC_active_exploitation_counts_as_confirmed_even_outside_KEV()
    {
        var decision = PriorityEngine.Evaluate(Rules, Inputs(ssvc: SsvcExploitation.Active, cvss: 8.1m));

        decision.Exploitation.Should().Be(ExploitationSignal.Active);
        decision.ExploitationSources.Should().Equal("SSVC:active");
        decision.Level.Should().Be(PriorityLevel.P1);
    }

    [Fact]
    public void SSVC_active_can_be_disabled_in_the_rule_set()
    {
        var rules = Rules with { SsvcActiveCountsAsExploited = false };

        var decision = PriorityEngine.Evaluate(rules, Inputs(ssvc: SsvcExploitation.Active, cvss: 8.1m));

        decision.Exploitation.Should().Be(ExploitationSignal.None);
    }

    [Theory]
    [InlineData(0.900, ExploitationSignal.Likely)] // exactly on the threshold
    [InlineData(0.899, ExploitationSignal.None)] // just below
    [InlineData(1.000, ExploitationSignal.Likely)]
    public void EPSS_threshold_is_inclusive(double percentile, ExploitationSignal expected)
    {
        PriorityEngine.ResolveExploitationSignal(Rules, Inputs(epssPercentile: (decimal)percentile)).Should().Be(expected);
    }

    [Fact]
    public void Missing_EPSS_is_treated_as_no_signal_and_explained()
    {
        var decision = PriorityEngine.Evaluate(Rules, Inputs(epssPercentile: null, cvss: 5.0m));

        decision.Exploitation.Should().Be(ExploitationSignal.None);
        decision.Reasons.Should().Contain(r => r.Contains("Sin dato EPSS", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(7.0, ImpactSignal.High)]
    [InlineData(6.9, ImpactSignal.Low)]
    [InlineData(0.0, ImpactSignal.Low)]
    public void CVSS_cut_off_for_high_impact_is_inclusive(double cvss, ImpactSignal expected)
    {
        PriorityEngine.ResolveImpact(Rules, Inputs(cvss: (decimal)cvss)).Should().Be(expected);
    }

    [Theory]
    [InlineData(Severity.Critical, ImpactSignal.High)]
    [InlineData(Severity.High, ImpactSignal.High)]
    [InlineData(Severity.Medium, ImpactSignal.Low)]
    [InlineData(Severity.Low, ImpactSignal.Low)]
    [InlineData(Severity.Unknown, ImpactSignal.High)] // assumption S3: conservative default
    public void Without_CVSS_the_textual_severity_decides(Severity severity, ImpactSignal expected)
    {
        PriorityEngine.ResolveImpact(Rules, Inputs(severity: severity)).Should().Be(expected);
    }

    [Fact]
    public void Unknown_severity_handling_is_configurable()
    {
        var rules = Rules with { UnknownSeverityAs = ImpactSignal.Low };

        PriorityEngine.ResolveImpact(rules, Inputs(severity: Severity.Unknown)).Should().Be(ImpactSignal.Low);
    }

    [Fact]
    public void CVSS_score_takes_precedence_over_textual_severity()
    {
        PriorityEngine.ResolveImpact(Rules, Inputs(cvss: 5.3m, severity: Severity.Critical)).Should().Be(ImpactSignal.Low);
    }

    [Fact]
    public void Explanation_lists_every_input_used()
    {
        var decision = PriorityEngine.Evaluate(Rules, Inputs(inKev: true, epssPercentile: 1.0m, cvss: 10.0m, severity: Severity.Critical, exposure: Exposure.Public, fixAvailable: true, fix: "2.15.0"));

        decision.Reasons.Should().HaveCount(6);
        decision.Reasons[0].Should().StartWith("R1:");
        decision.Reasons.Should().Contain("En el catálogo KEV de CISA desde 2021-12-10");
        decision.Reasons.Should().Contain("Proyecto expuesto públicamente");
        decision.Reasons.Should().Contain("Parche disponible: actualizar a 2.15.0");
    }

    [Fact]
    public void Evaluate_fails_loudly_if_a_custom_table_is_not_exhaustive()
    {
        var rules = Rules with { Rules = [new PriorityRule("ONLY", new([ExploitationSignal.Active]), PriorityLevel.P1, "Solo KEV")] };

        var act = () => PriorityEngine.Evaluate(rules, Inputs(cvss: 5.0m));

        act.Should().Throw<DomainException>();
    }
}
