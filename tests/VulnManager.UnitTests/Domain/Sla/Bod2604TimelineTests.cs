using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;

namespace VulnManager.UnitTests.Domain.Sla;

public class Bod2604TimelineTests
{
    public static TheoryData<bool, bool, bool, TechnicalImpact, int, int?, bool> Table1 => new()
    {
        // exposed, kev, automatable, impact, row, days, forensic triage (CISA BOD 26-04, Table 1)
        { true, true, true, TechnicalImpact.Total, 1, 3, true },
        { true, true, true, TechnicalImpact.Partial, 2, 3, false },
        { true, true, false, TechnicalImpact.Total, 3, 3, true },
        { true, true, false, TechnicalImpact.Partial, 4, 14, false },
        { true, false, true, TechnicalImpact.Total, 5, 3, false },
        { true, false, true, TechnicalImpact.Partial, 6, 14, false },
        { true, false, false, TechnicalImpact.Total, 7, 14, false },
        { true, false, false, TechnicalImpact.Partial, 8, 60, false },
        { false, true, true, TechnicalImpact.Total, 9, 3, true },
        { false, true, true, TechnicalImpact.Partial, 10, 14, false },
        { false, true, false, TechnicalImpact.Total, 11, 14, false },
        { false, true, false, TechnicalImpact.Partial, 12, 14, false },
        { false, false, true, TechnicalImpact.Total, 13, 60, false },
        { false, false, true, TechnicalImpact.Partial, 14, 60, false },
        { false, false, false, TechnicalImpact.Total, 15, null, false },
        { false, false, false, TechnicalImpact.Partial, 16, null, false },
    };

    [Theory]
    [MemberData(nameof(Table1))]
    public void Lookup_reproduces_every_row_of_table_1(bool exposed, bool kev, bool automatable, TechnicalImpact impact, int row, int? days, bool forensic)
    {
        var result = Bod2604Timeline.Lookup(exposed, kev, automatable, impact);

        result.Number.Should().Be(row);
        result.Days.Should().Be(days);
        result.ForensicTriage.Should().Be(forensic);
    }

    [Fact]
    public void Table_has_one_row_per_combination()
    {
        Bod2604Timeline.Rows.Should().HaveCount(16);
        Bod2604Timeline.Rows.Select(r => (r.PubliclyExposed, r.InKev, r.Automatable, r.TechnicalImpact)).Should().OnlyHaveUniqueItems();
        Bod2604Timeline.Rows.Where(r => r.ForensicTriage).Select(r => r.Number).Should().Equal(1, 3, 9);
    }
}
