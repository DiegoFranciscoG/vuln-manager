using System.Globalization;
using System.Text.Json;

namespace VulnManager.Infrastructure.External;

/// <summary>Defensive helpers: upstream JSON is untrusted input (OWASP API10:2023 Unsafe Consumption of APIs).</summary>
internal static class JsonReading
{
    public static string? Str(this JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static JsonElement? Obj(this JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Object
            ? value
            : null;

    public static IEnumerable<JsonElement> Arr(this JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
            : [];

    public static decimal? Dec(this JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetDecimal(out var d) => d,
            JsonValueKind.String when decimal.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var s) => s,
            _ => null,
        };
    }

    public static DateTimeOffset? Date(this JsonElement element, string property) =>
        DateTimeOffset.TryParse(element.Str(property), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
            ? value
            : null;

    public static DateOnly? DateOnlyValue(this JsonElement element, string property) =>
        DateOnly.TryParseExact(element.Str(property), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var value) ? value : null;

    public static string? Clip(string? value, int max) => value is null ? null : value.Length > max ? value[..max] : value;

    public static readonly JsonDocumentOptions DocumentOptions = new() { MaxDepth = 64 };
}
