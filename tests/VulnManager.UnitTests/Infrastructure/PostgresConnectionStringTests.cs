using Npgsql;
using VulnManager.Infrastructure.Persistence;

namespace VulnManager.UnitTests.Infrastructure;

public class PostgresConnectionStringTests
{
    private const string FakePassword = "p@ss:w0rd/x";

    [Fact]
    public void Neon_style_uri_is_converted_with_tls_and_channel_binding()
    {
        var uri = UriWithPassword("ep-demo-123.us-east-2.aws.neon.tech", "vulnmanager", "sslmode=require&channel_binding=require");

        var builder = new NpgsqlConnectionStringBuilder(PostgresConnectionString.Normalize(uri));

        builder.Host.Should().Be("ep-demo-123.us-east-2.aws.neon.tech");
        builder.Port.Should().Be(5432);
        builder.Database.Should().Be("vulnmanager");
        builder.Username.Should().Be("demo_user");
        builder.Password.Should().Be(FakePassword);
        builder.SslMode.Should().Be(SslMode.Require);
        builder.ChannelBinding.Should().Be(ChannelBinding.Require);
        builder.GssEncryptionMode.Should().Be(GssEncryptionMode.Disable);
    }

    [Fact]
    public void Uri_with_explicit_port_and_verify_full_is_supported()
    {
        var builder = new NpgsqlConnectionStringBuilder(PostgresConnectionString.Normalize("postgres://demo@db.internal:6543/app?sslmode=verify-full"));

        builder.Port.Should().Be(6543);
        builder.SslMode.Should().Be(SslMode.VerifyFull);
        builder.Password.Should().BeNull();
    }

    [Fact]
    public void Key_value_format_is_kept_and_gss_is_disabled()
    {
        var builder = new NpgsqlConnectionStringBuilder(PostgresConnectionString.Normalize("Host=db;Port=5432;Database=vulnmanager;Username=vulnmanager"));

        builder.Host.Should().Be("db");
        builder.Database.Should().Be("vulnmanager");
        builder.GssEncryptionMode.Should().Be(GssEncryptionMode.Disable);
    }

    [Fact]
    public void Unknown_uri_parameters_fail_fast_without_echoing_credentials()
    {
        var act = () => PostgresConnectionString.Normalize(UriWithPassword("db", "app", "pool=big"));

        act.Should().Throw<InvalidOperationException>().Which.Message.Should().Contain("pool").And.NotContain("w0rd");
    }

    // Built from parts so the source never contains a literal URI with credentials (gitleaks rule uri-con-credenciales).
    private static string UriWithPassword(string host, string database, string query) =>
        new UriBuilder("postgresql", host) { UserName = "demo_user", Password = Uri.EscapeDataString(FakePassword), Path = database, Query = query }.Uri.AbsoluteUri;
}
