using VulnManager.Domain.Vex;

namespace VulnManager.UnitTests.Domain.Vex;

public class VexRulesTests
{
    private static VexStatementDraft Draft(
        VexStatus status = VexStatus.NotAffected,
        VexJustificationScheme? scheme = VexJustificationScheme.Cisa,
        string? justification = "vulnerable_code_not_in_execute_path",
        string? impact = null,
        string? action = null,
        string vulnerability = "CVE-2021-44228",
        string? purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") =>
        new(status, scheme, justification, impact, action, vulnerability, purl);

    [Fact]
    public void Not_affected_with_a_CISA_justification_is_valid()
    {
        VexStatementRules.Validate(Draft()).Should().BeEmpty();
    }

    [Fact]
    public void Not_affected_with_only_an_impact_statement_is_valid()
    {
        VexStatementRules.Validate(Draft(scheme: null, justification: null, impact: "JndiLookup.class eliminada del classpath")).Should().BeEmpty();
    }

    [Fact]
    public void Not_affected_without_justification_nor_impact_statement_is_rejected()
    {
        VexStatementRules.Validate(Draft(scheme: null, justification: null)).Should().ContainSingle()
            .Which.Should().Contain("requiere una justificación");
    }

    [Fact]
    public void Affected_requires_an_action_statement()
    {
        VexStatementRules.Validate(Draft(status: VexStatus.Affected, scheme: null, justification: null)).Should().ContainSingle()
            .Which.Should().Contain("declaración de acción");
    }

    [Fact]
    public void CycloneDX_justifications_are_validated_against_their_own_vocabulary()
    {
        VexStatementRules.Validate(Draft(scheme: VexJustificationScheme.CycloneDx, justification: "code_not_reachable")).Should().BeEmpty();
        VexStatementRules.Validate(Draft(scheme: VexJustificationScheme.Cisa, justification: "code_not_reachable")).Should().ContainSingle();
    }

    [Fact]
    public void Justification_needs_a_scheme()
    {
        VexStatementRules.Validate(Draft(scheme: null)).Should().ContainSingle().Which.Should().Contain("vocabulario");
    }

    [Theory]
    [InlineData("")]
    [InlineData("CVE-2021-44228-THIS-IS-A-VERY-LONG-IDENTIFIER-OVER-50")]
    public void Vulnerability_reference_is_required_and_bounded(string reference)
    {
        VexStatementRules.Validate(Draft(vulnerability: reference)).Should().NotBeEmpty();
    }

    [Fact]
    public void Component_purl_must_be_valid_when_present()
    {
        VexStatementRules.Validate(Draft(purl: "not-a-purl")).Should().ContainSingle();
        VexStatementRules.Validate(Draft(purl: null)).Should().BeEmpty();
    }

    [Fact]
    public void Statements_have_a_maximum_length()
    {
        VexStatementRules.Validate(Draft(impact: new string('x', 2001))).Should().ContainSingle();
    }
}
