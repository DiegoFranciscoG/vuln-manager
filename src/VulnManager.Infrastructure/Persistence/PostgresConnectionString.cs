using Npgsql;

namespace VulnManager.Infrastructure.Persistence;

/// <summary>
/// Accepts both the Npgsql key/value format and the URI format shown by Neon and Render
/// (postgresql://user:password@host:port/database?sslmode=require&amp;channel_binding=require).
/// </summary>
public static class PostgresConnectionString
{
    public static string Normalize(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var builder = IsUri(value) ? FromUri(new Uri(value.Trim())) : new NpgsqlConnectionStringBuilder(value);

        // Kerberos/GSS is never used (Neon and local use password + TLS); disabling it avoids probing for libgssapi,
        // which the chiseled runtime image does not ship.
        builder.GssEncryptionMode = GssEncryptionMode.Disable;
        return builder.ConnectionString;
    }

    private static bool IsUri(string value) =>
        value.TrimStart().StartsWith("postgres://", StringComparison.OrdinalIgnoreCase)
        || value.TrimStart().StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase);

    private static NpgsqlConnectionStringBuilder FromUri(Uri uri)
    {
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = uri.Host.Trim('[', ']'),
            Port = uri.Port > 0 ? uri.Port : 5432,
            Database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')),
        };

        var credentials = uri.UserInfo.Split(':', 2);
        builder.Username = Uri.UnescapeDataString(credentials[0]);
        if (credentials.Length == 2)
        {
            builder.Password = Uri.UnescapeDataString(credentials[1]);
        }

        foreach (var parameter in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = parameter.Split('=', 2);
            var name = Uri.UnescapeDataString(parts[0]);
            var setting = parts.Length == 2 ? Uri.UnescapeDataString(parts[1]) : string.Empty;
            switch (name.ToUpperInvariant())
            {
                case "SSLMODE":
                    builder.SslMode = Enum.Parse<SslMode>(setting.Replace("-", string.Empty, StringComparison.Ordinal), ignoreCase: true);
                    break;
                case "CHANNEL_BINDING":
                    builder.ChannelBinding = Enum.Parse<ChannelBinding>(setting, ignoreCase: true);
                    break;
                case "OPTIONS":
                    builder.Options = setting;
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported parameter '{name}' in the PostgreSQL connection URI.");
            }
        }

        return builder;
    }
}
