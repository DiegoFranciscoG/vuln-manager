using VulnManager.Application.Exceptions;
using VulnManager.Infrastructure.Parsing;
using VulnManager.UnitTests.TestSupport;

namespace VulnManager.UnitTests.Infrastructure;

public class CycloneDxParserTests
{
    private readonly CycloneDxParser _parser = new();

    [Fact]
    public void Parses_components_normalizes_purls_and_counts_skipped_ones()
    {
        var bom = _parser.Parse(Fixtures.Read("sbom/portal-log4j-2.14.1.cdx.json"));

        bom.SpecVersion.Should().Be("1.6");
        bom.SerialNumber.Should().Be("urn:uuid:6f8a2c1e-1d2b-4c3a-9e4f-0a1b2c3d4e5f");
        bom.Components.Select(c => c.Purl).Should().Equal(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "pkg:npm/left-pad@1.3.0");
        bom.Components[0].BomRef.Should().Be("log4j-core");
        bom.Components[0].Scope.Should().Be("required");
        bom.SkippedComponents.Should().Be(1, "a component without purl cannot be matched");
    }

    [Fact]
    public void Extracts_VEX_analysis_with_CycloneDX_vocabulary()
    {
        var bom = _parser.Parse(Fixtures.Read("sbom/portal-vex-45046.cdx.json"));

        var vex = bom.Vex.Should().ContainSingle().Subject;
        vex.VulnerabilityId.Should().Be("CVE-2021-45046");
        vex.State.Should().Be("not_affected");
        vex.Justification.Should().Be("code_not_reachable");
        vex.AffectsRefs.Should().Equal("log4j-core");
    }

    [Fact]
    public void Flattens_nested_components_and_deduplicates()
    {
        const string json = """
        {"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
          {"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0","components":[
            {"type":"library","name":"b","version":"2.0.0","purl":"pkg:npm/b@2.0.0"}]},
          {"type":"library","name":"a","version":"1.0.0","purl":"pkg:npm/a@1.0.0?arch=x64"}]}
        """;

        var bom = _parser.Parse(json);

        bom.Components.Select(c => c.Purl).Should().Equal("pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0");
    }

    [Theory]
    [InlineData("""{"bomFormat":"SPDX","specVersion":"1.6"}""", "No es un documento CycloneDX")]
    [InlineData("""{"bomFormat":"CycloneDX","specVersion":"1.2"}""", "no soportada")]
    [InlineData("""{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"nope","name":1}]}""", "no cumple el esquema")]
    [InlineData("not json", "no es JSON")]
    [InlineData("[]", "No es un documento CycloneDX")]
    public void Rejects_documents_that_are_not_valid_CycloneDX(string json, string message)
    {
        var act = () => _parser.Parse(json);

        act.Should().Throw<InvalidInputException>().WithMessage($"*{message}*");
    }

    [Fact]
    public void Rejects_excessive_nesting_depth()
    {
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 80)) + "1" + new string('}', 80);
        var json = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"x\":" + deep + "}";

        var act = () => _parser.Parse(json);

        act.Should().Throw<InvalidInputException>();
    }
}
