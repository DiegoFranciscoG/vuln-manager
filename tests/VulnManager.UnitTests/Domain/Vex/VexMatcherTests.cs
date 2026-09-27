using VulnManager.Domain.Packages;
using VulnManager.Domain.Vex;

namespace VulnManager.UnitTests.Domain.Vex;

public class VexMatcherTests
{
    private static readonly PackageUrl Log4j = PackageUrl.Parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar");
    private static readonly DateTimeOffset T0 = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    private static VexCandidate Candidate(string? purl, string vuln = "CVE-2021-44228", int minutes = 0, bool revoked = false, VexStatus status = VexStatus.NotAffected) =>
        new(Guid.NewGuid(), vuln, purl, status, T0.AddMinutes(minutes), revoked);

    private static VexCandidate? Select(params VexCandidate[] candidates) =>
        VexMatcher.SelectApplicable(candidates, "GHSA-jfh8-c2jp-5v3q", ["CVE-2021-44228"], Log4j);

    [Fact]
    public void Exact_version_beats_versionless_which_beats_project_wide()
    {
        var projectWide = Candidate(null, minutes: 30);
        var anyVersion = Candidate("pkg:maven/org.apache.logging.log4j/log4j-core", minutes: 20);
        var exact = Candidate("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", minutes: 10);

        Select(projectWide, anyVersion, exact).Should().Be(exact);
        Select(projectWide, anyVersion).Should().Be(anyVersion);
        Select(projectWide).Should().Be(projectWide);
    }

    [Fact]
    public void Matches_by_osv_id_or_alias_case_insensitively()
    {
        var byAlias = Candidate(null, vuln: "cve-2021-44228");
        var byId = Candidate(null, vuln: "GHSA-jfh8-c2jp-5v3q");

        Select(byAlias).Should().Be(byAlias);
        Select(byId).Should().Be(byId);
    }

    [Fact]
    public void Most_recent_statement_wins_at_the_same_specificity()
    {
        var older = Candidate(null, minutes: 1, status: VexStatus.NotAffected);
        var newer = Candidate(null, minutes: 5, status: VexStatus.Affected);

        Select(older, newer).Should().Be(newer);
    }

    [Fact]
    public void Revoked_statements_and_other_components_are_ignored()
    {
        var revoked = Candidate("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", revoked: true);
        var otherVersion = Candidate("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1");
        var otherPackage = Candidate("pkg:maven/org.apache.logging.log4j/log4j-api");
        var otherVuln = Candidate(null, vuln: "CVE-2021-45046");

        Select(revoked, otherVersion, otherPackage, otherVuln).Should().BeNull();
    }
}
