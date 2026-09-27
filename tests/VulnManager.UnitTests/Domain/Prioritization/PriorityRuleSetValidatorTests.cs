using VulnManager.Domain.Common;
using VulnManager.Domain.Prioritization;

namespace VulnManager.UnitTests.Domain.Prioritization;

public class PriorityRuleSetValidatorTests
{
    private static readonly PriorityRuleSet Default = PriorityRuleSet.Default;

    [Fact]
    public void Default_rule_set_is_valid()
    {
        PriorityRuleSetValidator.Validate(Default).Should().BeEmpty();
    }

    [Fact]
    public void Removing_the_catch_all_rule_leaves_combinations_uncovered()
    {
        var rules = Default with { Rules = Default.Rules.Where(r => r.Id != "R7").ToList() };

        var errors = PriorityRuleSetValidator.Validate(rules);

        errors.Should().Contain(e => e.StartsWith("Ninguna regla cubre", StringComparison.Ordinal));
    }

    [Fact]
    public void A_rule_shadowed_by_earlier_rules_is_reported_as_unreachable()
    {
        var shadowed = new PriorityRule("R8", new([ExploitationSignal.None]), PriorityLevel.P2, "Nunca se evalúa");
        var rules = Default with { Rules = [.. Default.Rules, shadowed] };

        PriorityRuleSetValidator.Validate(rules).Should().Contain(e => e.Contains("R8 nunca se aplica", StringComparison.Ordinal));
    }

    [Fact]
    public void Duplicate_ids_are_rejected()
    {
        var rules = Default with { Rules = [Default.Rules[0], Default.Rules[0] with { Level = PriorityLevel.P2 }, .. Default.Rules.Skip(1)] };

        PriorityRuleSetValidator.Validate(rules).Should().Contain(e => e.StartsWith("Id de regla duplicado", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(1.01)]
    public void EPSS_threshold_must_be_a_percentile(double threshold)
    {
        var rules = Default with { EpssPercentileThreshold = (decimal)threshold };

        PriorityRuleSetValidator.Validate(rules).Should().NotBeEmpty();
    }

    [Fact]
    public void Empty_condition_lists_are_rejected()
    {
        var rules = Default with { Rules = [new PriorityRule("R0", new(Exposure: Array.Empty<Exposure>()), PriorityLevel.P1, "Vacía"), .. Default.Rules] };

        PriorityRuleSetValidator.Validate(rules).Should().Contain(e => e.Contains("condición vacía", StringComparison.Ordinal));
    }

    [Fact]
    public void EnsureValid_throws_a_domain_exception_with_all_errors()
    {
        var act = () => PriorityRuleSetValidator.EnsureValid(Default with { Rules = [] });

        act.Should().Throw<DomainException>();
    }

    [Fact]
    public void AllCombinations_enumerates_3_by_2_by_2_cases()
    {
        PriorityRuleSetValidator.AllCombinations().Should().HaveCount(12).And.OnlyHaveUniqueItems();
    }
}
