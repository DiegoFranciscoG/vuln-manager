namespace VulnManager.Infrastructure.Persistence;

/// <summary>Escapes LIKE/ILIKE wildcards so user input is always matched literally (the value is still a SQL parameter).</summary>
internal static class LikePattern
{
    public const string EscapeCharacter = @"\";

    public static string Escape(string value) =>
        value.Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("%", @"\%", StringComparison.Ordinal)
            .Replace("_", @"\_", StringComparison.Ordinal);
}
