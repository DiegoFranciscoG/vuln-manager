using System.Text;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace VulnManager.Infrastructure.Persistence.Converters;

/// <summary>Stores enums as UPPER_SNAKE strings ("FALSE_POSITIVE", "P1") so the database stays readable and CHECK constraints are explicit.</summary>
public static class EnumDbNames
{
    public static string ToUpperSnake(string pascal)
    {
        ArgumentNullException.ThrowIfNull(pascal);
        var builder = new StringBuilder(pascal.Length + 8);
        for (var i = 0; i < pascal.Length; i++)
        {
            var c = pascal[i];
            if (i > 0 && char.IsUpper(c) && (char.IsLower(pascal[i - 1]) || (i + 1 < pascal.Length && char.IsLower(pascal[i + 1]) && char.IsUpper(pascal[i - 1]))))
            {
                builder.Append('_');
            }

            builder.Append(char.ToUpperInvariant(c));
        }

        return builder.ToString();
    }

    public static IReadOnlyList<string> ValuesOf<TEnum>()
        where TEnum : struct, Enum =>
        Enum.GetValues<TEnum>().Select(v => ToUpperSnake(v.ToString())).ToArray();

    /// <summary>SQL for a CHECK constraint restricting a column to the enum values.</summary>
    public static string CheckSql<TEnum>(string column, bool nullable = false)
        where TEnum : struct, Enum
    {
        var list = string.Join(", ", ValuesOf<TEnum>().Select(v => $"'{v}'"));
        return nullable ? $"{column} IS NULL OR {column} IN ({list})" : $"{column} IN ({list})";
    }
}

public sealed class UpperSnakeEnumConverter<TEnum> : ValueConverter<TEnum, string>
    where TEnum : struct, Enum
{
    private static readonly Dictionary<TEnum, string> ToDatabase =
        Enum.GetValues<TEnum>().ToDictionary(v => v, v => EnumDbNames.ToUpperSnake(v.ToString()));

    private static readonly Dictionary<string, TEnum> FromDatabase =
        ToDatabase.ToDictionary(kv => kv.Value, kv => kv.Key, StringComparer.Ordinal);

    public UpperSnakeEnumConverter()
        : base(v => Write(v), v => Read(v))
    {
    }

    private static string Write(TEnum value) => ToDatabase[value];

    private static TEnum Read(string value) =>
        FromDatabase.TryGetValue(value, out var parsed) ? parsed : throw new InvalidOperationException($"Unknown {typeof(TEnum).Name} value '{value}'.");
}
