using VulnManager.Domain.Findings;

namespace VulnManager.UnitTests.Domain.Findings;

public class FindingTransitionsTests
{
    private static readonly DateOnly Today = new(2026, 9, 26);
    private const string Reason = "Control compensatorio aplicado en el WAF";

    private static IReadOnlyList<string> Check(
        FindingStatus from,
        FindingStatus to,
        StatusChangeSource source = StatusChangeSource.User,
        string? justification = Reason,
        DateOnly? until = null) =>
        FindingTransitions.Check(new TransitionRequest(from, to, source, justification, until, Today, 90));

    [Theory]
    [InlineData(FindingStatus.New, FindingStatus.Mitigated)]
    [InlineData(FindingStatus.New, FindingStatus.FalsePositive)]
    [InlineData(FindingStatus.Mitigated, FindingStatus.New)]
    [InlineData(FindingStatus.FalsePositive, FindingStatus.New)]
    [InlineData(FindingStatus.NotAffected, FindingStatus.New)]
    [InlineData(FindingStatus.Accepted, FindingStatus.New)]
    public void Users_can_triage_and_reopen(FindingStatus from, FindingStatus to)
    {
        Check(from, to).Should().BeEmpty();
    }

    [Theory]
    [InlineData(FindingStatus.New, FindingStatus.Fixed)] // only the system closes as fixed
    [InlineData(FindingStatus.New, FindingStatus.NotAffected)] // requires a VEX statement
    [InlineData(FindingStatus.Fixed, FindingStatus.New)] // regressions are detected by SBOM import
    [InlineData(FindingStatus.Mitigated, FindingStatus.FalsePositive)] // reopen first
    public void Users_cannot_bypass_system_or_VEX_transitions(FindingStatus from, FindingStatus to)
    {
        Check(from, to).Should().ContainSingle().Which.Should().StartWith("Transición no permitida");
    }

    [Fact]
    public void Same_status_is_rejected()
    {
        Check(FindingStatus.New, FindingStatus.New).Should().ContainSingle();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("corto")]
    public void User_transitions_require_a_justification(string? justification)
    {
        Check(FindingStatus.New, FindingStatus.Mitigated, justification: justification).Should().ContainSingle()
            .Which.Should().StartWith("La justificación es obligatoria");
    }

    [Fact]
    public void Justification_has_a_maximum_length()
    {
        Check(FindingStatus.New, FindingStatus.Mitigated, justification: new string('x', 1001)).Should().ContainSingle();
    }

    [Fact]
    public void Risk_acceptance_requires_an_expiry_date()
    {
        Check(FindingStatus.New, FindingStatus.Accepted).Should().ContainSingle().Which.Should().Contain("fecha de expiración");
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(90, true)]
    [InlineData(0, false)] // today is not in the future
    [InlineData(91, false)] // beyond the maximum
    public void Risk_acceptance_expiry_must_be_within_the_window(int daysAhead, bool valid)
    {
        var errors = Check(FindingStatus.New, FindingStatus.Accepted, until: Today.AddDays(daysAhead));

        (errors.Count == 0).Should().Be(valid);
    }

    [Theory]
    [InlineData(FindingStatus.New, FindingStatus.Fixed, StatusChangeSource.SbomImport)]
    [InlineData(FindingStatus.Accepted, FindingStatus.Fixed, StatusChangeSource.SbomImport)]
    [InlineData(FindingStatus.Fixed, FindingStatus.New, StatusChangeSource.SbomImport)]
    [InlineData(FindingStatus.New, FindingStatus.NotAffected, StatusChangeSource.Vex)]
    [InlineData(FindingStatus.NotAffected, FindingStatus.New, StatusChangeSource.Vex)]
    [InlineData(FindingStatus.New, FindingStatus.Fixed, StatusChangeSource.Vex)]
    [InlineData(FindingStatus.New, FindingStatus.Fixed, StatusChangeSource.Sync)]
    [InlineData(FindingStatus.Accepted, FindingStatus.New, StatusChangeSource.Expiry)]
    public void System_sources_have_their_own_transitions_without_justification(FindingStatus from, FindingStatus to, StatusChangeSource source)
    {
        Check(from, to, source, justification: null).Should().BeEmpty();
    }

    [Theory]
    [InlineData(FindingStatus.Fixed, FindingStatus.NotAffected, StatusChangeSource.Vex)]
    [InlineData(FindingStatus.New, FindingStatus.New, StatusChangeSource.Expiry)]
    [InlineData(FindingStatus.Mitigated, FindingStatus.New, StatusChangeSource.Expiry)]
    [InlineData(FindingStatus.Fixed, FindingStatus.Fixed, StatusChangeSource.Sync)]
    public void System_sources_are_also_constrained(FindingStatus from, FindingStatus to, StatusChangeSource source)
    {
        Check(from, to, source, justification: null).Should().NotBeEmpty();
    }
}
