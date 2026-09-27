using VulnManager.Domain.Scoring;
using VulnManager.Domain.Sla;

namespace VulnManager.UnitTests.Domain.Sla;

public class SsvcProxyTests
{
    [Fact]
    public void CISA_values_take_precedence_over_the_CVSS_proxy()
    {
        var facts = SsvcProxy.Resolve(false, TechnicalImpact.Partial, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

        facts.Should().Be(new SsvcFacts(false, SsvcDataSource.CisaAdp, TechnicalImpact.Partial, SsvcDataSource.CisaAdp));
    }

    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, TechnicalImpact.Total)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", false, TechnicalImpact.Partial)]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", false, TechnicalImpact.Total)]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", true, TechnicalImpact.Total)]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AU:N", false, TechnicalImpact.Total)]
    [InlineData("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/AU:Y", true, TechnicalImpact.Partial)]
    public void FromCvss_infers_decision_points(string vector, bool automatable, TechnicalImpact impact)
    {
        var (a, t) = SsvcProxy.FromCvss(vector);

        a.Should().Be(automatable);
        t.Should().Be(impact);
    }

    [Fact]
    public void FromCvss_returns_nothing_for_unparseable_vectors()
    {
        SsvcProxy.FromCvss("not-a-vector").Should().Be(((bool?)null, (TechnicalImpact?)null));
    }
}
