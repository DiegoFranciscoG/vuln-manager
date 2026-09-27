using VulnManager.Application.Abstractions.External;
using VulnManager.Application.Sync;

namespace VulnManager.UnitTests.Application;

public class AliasDeduplicatorTests
{
    private static OsvVulnerability Record(string id, params string[] aliases) =>
        new(id, DateTimeOffset.UnixEpoch, null, null, aliases, null, null, [], null, []);

    [Fact]
    public void GHSA_and_PYSEC_records_for_the_same_CVE_collapse_into_the_GHSA()
    {
        // Real case seen in OSV for PyYAML 5.3.1 (CVE-2020-14343).
        var result = AliasDeduplicator.Representatives([Record("PYSEC-2021-142", "CVE-2020-14343", "GHSA-8q59-q68h-6hv4"), Record("GHSA-8q59-q68h-6hv4", "CVE-2020-14343")]);

        result.Should().ContainSingle().Which.Id.Should().Be("GHSA-8q59-q68h-6hv4");
    }

    [Fact]
    public void Records_sharing_only_a_CVE_alias_are_grouped()
    {
        var result = AliasDeduplicator.Representatives([Record("GHSA-r5fr-rjxr-66jc", "CVE-2021-23337"), Record("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337")]);

        result.Should().ContainSingle().Which.Id.Should().Be("GHSA-35jh-r3h4-6jhm", "ties are broken by id to stay deterministic");
    }

    [Fact]
    public void Transitive_aliases_are_grouped()
    {
        var result = AliasDeduplicator.Representatives([Record("A-1", "X-1"), Record("B-1", "X-1", "Y-1"), Record("CVE-2024-0001", "Y-1")]);

        result.Should().ContainSingle().Which.Id.Should().Be("CVE-2024-0001");
    }

    [Fact]
    public void Unrelated_records_are_kept()
    {
        var result = AliasDeduplicator.Representatives([Record("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"), Record("GHSA-7rjr-3q55-vv33", "CVE-2021-45046")]);

        result.Should().HaveCount(2);
    }
}
