using VulnManager.Domain.Packages;

namespace VulnManager.UnitTests.Domain.Packages;

public class PackageUrlTests
{
    [Fact]
    public void Parse_splits_every_component_and_sorts_qualifiers()
    {
        var purl = PackageUrl.Parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar&classifier=sources#src/main");

        purl.Type.Should().Be("maven");
        purl.Namespace.Should().Be("org.apache.logging.log4j");
        purl.Name.Should().Be("log4j-core");
        purl.Version.Should().Be("2.14.1");
        purl.Qualifiers.Keys.Should().Equal("classifier", "type");
        purl.Subpath.Should().Be("src/main");
        purl.ToString().Should().Be("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?classifier=sources&type=jar#src/main");
    }

    [Fact]
    public void Coordinates_drop_qualifiers_and_subpath_so_tools_map_to_one_component()
    {
        var fromSyft = PackageUrl.Parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar");
        var fromCdxgen = PackageUrl.Parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");

        fromSyft.Coordinates.Should().Be(fromCdxgen.Coordinates);
        fromSyft.VersionlessCoordinates.Should().Be("pkg:maven/org.apache.logging.log4j/log4j-core");
    }

    [Theory]
    [InlineData("pkg:npm/@angular/core@16.2.0")]
    [InlineData("pkg:npm/%40angular/core@16.2.0")]
    [InlineData("PKG:NPM/@Angular/Core@16.2.0")]
    public void Parse_normalizes_scoped_npm_packages(string value)
    {
        var purl = PackageUrl.Parse(value);

        purl.Namespace.Should().Be("@angular");
        purl.Name.Should().Be("core");
        purl.Version.Should().Be("16.2.0");
        purl.Coordinates.Should().Be("pkg:npm/%40angular/core@16.2.0");
    }

    [Fact]
    public void Parse_applies_pypi_name_normalization()
    {
        PackageUrl.Parse("pkg:pypi/Django_Rest_Framework@3.14.0").Name.Should().Be("django-rest-framework");
    }

    [Fact]
    public void Parse_keeps_case_for_case_sensitive_types()
    {
        var purl = PackageUrl.Parse("pkg:nuget/Newtonsoft.Json@12.0.1");

        purl.Name.Should().Be("Newtonsoft.Json");
        purl.Namespace.Should().BeNull();
    }

    [Fact]
    public void Parse_accepts_packages_without_version()
    {
        var purl = PackageUrl.Parse("pkg:npm/lodash");

        purl.Version.Should().BeNull();
        purl.Coordinates.Should().Be("pkg:npm/lodash");
    }

    [Fact]
    public void Equality_uses_the_canonical_form()
    {
        PackageUrl.Parse("pkg:npm/lodash@4.17.15?b=2&a=1").Should().Be(PackageUrl.Parse("pkg:NPM/lodash@4.17.15?a=1&b=2"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("maven/org.example/lib@1.0")]
    [InlineData("pkg:maven")]
    [InlineData("pkg:/lib@1.0")]
    [InlineData("pkg:1bad/lib@1.0")]
    [InlineData("pkg:npm/lodash@1.0?novalue")]
    public void TryParse_rejects_invalid_values(string? value)
    {
        PackageUrl.TryParse(value, out _).Should().BeFalse();
    }
}
