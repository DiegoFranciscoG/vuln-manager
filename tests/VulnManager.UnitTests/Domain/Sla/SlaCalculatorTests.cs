using VulnManager.Domain.Common;
using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;

namespace VulnManager.UnitTests.Domain.Sla;

public class SlaCalculatorTests
{
    private static readonly DateTimeOffset Detected = new(2026, 9, 26, 15, 0, 0, TimeSpan.Zero);

    private static SlaInputs Inputs(
        Exposure exposure = Exposure.Public,
        bool inKev = false,
        DateOnly? kevAdded = null,
        bool? automatable = null,
        TechnicalImpact? impact = null,
        string? vector = null,
        Severity severity = Severity.Unknown) =>
        new(exposure, inKev, kevAdded, automatable, impact, vector, severity, Detected);

    [Fact]
    public void Log4Shell_on_a_public_service_is_row_1_and_the_clock_starts_on_the_KEV_date()
    {
        var decision = SlaCalculator.Calculate(SlaSettings.Default, Inputs(inKev: true, kevAdded: new DateOnly(2021, 12, 10), automatable: true, impact: TechnicalImpact.Total));

        decision.Row.Should().Be(1);
        decision.Days.Should().Be(3);
        decision.ForensicTriageRequired.Should().BeTrue();
        decision.StartBasis.Should().Be(SlaCalculator.StartBasisKev);
        decision.StartedAt.Should().Be(new DateTimeOffset(2021, 12, 10, 0, 0, 0, TimeSpan.Zero));
        decision.DueAt.Should().Be(new DateTimeOffset(2021, 12, 13, 0, 0, 0, TimeSpan.Zero));
        decision.Ssvc!.AutomatableSource.Should().Be(SsvcDataSource.CisaAdp);
    }

    [Fact]
    public void KEV_addition_after_detection_keeps_the_detection_date_but_shortens_the_deadline()
    {
        var before = SlaCalculator.Calculate(SlaSettings.Default, Inputs(automatable: false, impact: TechnicalImpact.Partial));
        var after = SlaCalculator.Calculate(SlaSettings.Default, Inputs(inKev: true, kevAdded: new DateOnly(2026, 10, 1), automatable: false, impact: TechnicalImpact.Partial));

        before.Row.Should().Be(8);
        before.DueAt.Should().Be(Detected.AddDays(60));
        after.Row.Should().Be(4);
        after.StartBasis.Should().Be(SlaCalculator.StartBasisDetection);
        after.DueAt.Should().Be(Detected.AddDays(14));
    }

    [Fact]
    public void Removing_public_exposure_moves_the_deadline_back()
    {
        var exposed = SlaCalculator.Calculate(SlaSettings.Default, Inputs(automatable: true, impact: TechnicalImpact.Total));
        var internalOnly = SlaCalculator.Calculate(SlaSettings.Default, Inputs(exposure: Exposure.Internal, automatable: true, impact: TechnicalImpact.Total));

        exposed.Days.Should().Be(3);
        internalOnly.Days.Should().Be(60);
    }

    [Fact]
    public void Fix_on_system_upgrade_rows_have_no_due_date_by_default()
    {
        var decision = SlaCalculator.Calculate(SlaSettings.Default, Inputs(exposure: Exposure.Internal, automatable: false, impact: TechnicalImpact.Total));

        decision.Row.Should().Be(15);
        decision.Days.Should().BeNull();
        decision.DueAt.Should().BeNull();
    }

    [Fact]
    public void Fix_on_system_upgrade_can_get_an_optional_deadline()
    {
        var settings = SlaSettings.Default with { FixOnUpgradeDays = 180 };

        var decision = SlaCalculator.Calculate(settings, Inputs(exposure: Exposure.Internal, automatable: false, impact: TechnicalImpact.Partial));

        decision.Row.Should().Be(16);
        decision.DueAt.Should().Be(Detected.AddDays(180));
    }

    [Fact]
    public void Missing_CISA_data_uses_the_CVSS_proxy()
    {
        var decision = SlaCalculator.Calculate(SlaSettings.Default, Inputs(vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));

        decision.Row.Should().Be(5);
        decision.Ssvc!.AutomatableSource.Should().Be(SsvcDataSource.CvssProxy);
        decision.Ssvc.TechnicalImpactSource.Should().Be(SsvcDataSource.CvssProxy);
    }

    [Fact]
    public void Missing_everything_falls_back_to_the_conservative_default()
    {
        var decision = SlaCalculator.Calculate(SlaSettings.Default, Inputs());

        decision.Row.Should().Be(7); // public, not KEV, automatable = no, impact = total
        decision.Ssvc!.AutomatableSource.Should().Be(SsvcDataSource.Default);
    }

    [Theory]
    [InlineData(Severity.Critical, 15)]
    [InlineData(Severity.High, 30)]
    [InlineData(Severity.Medium, 90)]
    [InlineData(Severity.Low, 180)]
    [InlineData(Severity.Unknown, 30)]
    public void Severity_policy_uses_fixed_days(Severity severity, int days)
    {
        var settings = SlaSettings.Default with { Policy = SlaPolicyType.Severity };

        var decision = SlaCalculator.Calculate(settings, Inputs(severity: severity));

        decision.Policy.Should().Be(SlaPolicyType.Severity);
        decision.Row.Should().BeNull();
        decision.DueAt.Should().Be(Detected.AddDays(days));
    }
}
