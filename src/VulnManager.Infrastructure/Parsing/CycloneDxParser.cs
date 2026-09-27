using System.Text.Json;
using CycloneDX;
using CycloneDX.Models;
using VulnManager.Application.Abstractions;
using VulnManager.Application.Exceptions;
using VulnManager.Domain.Packages;
using CdxJson = CycloneDX.Json;

namespace VulnManager.Infrastructure.Parsing;

/// <summary>
/// Parses CycloneDX JSON 1.4-1.7 with the official CycloneDX .NET library: schema validation first, then extraction of
/// components (nested included, metadata.component excluded) and VEX analysis entries.
/// </summary>
public sealed class CycloneDxParser : ICycloneDxParser
{
    public const int MaxComponents = 20_000;

    private static readonly Dictionary<string, SpecificationVersion> Supported = new(StringComparer.Ordinal)
    {
        ["1.4"] = SpecificationVersion.v1_4,
        ["1.5"] = SpecificationVersion.v1_5,
        ["1.6"] = SpecificationVersion.v1_6,
        ["1.7"] = SpecificationVersion.v1_7,
    };

    public ParsedBom Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var specVersion = ReadHeader(json);

        var validation = CdxJson.Validator.Validate(json, Supported[specVersion]);
        if (!validation.Valid)
        {
            var detail = string.Join(" ", (validation.Messages ?? []).Skip(1).Take(3));
            throw new InvalidInputException($"El documento no cumple el esquema CycloneDX {specVersion}. {detail}".Trim());
        }

        Bom bom;
        try
        {
            bom = CdxJson.Serializer.Deserialize(json);
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException("No se pudo leer el documento CycloneDX.", ex);
        }

        var components = new List<ParsedComponent>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var skipped = 0;
        foreach (var component in Flatten(bom.Components))
        {
            if (components.Count >= MaxComponents)
            {
                throw new InvalidInputException($"El SBOM supera el máximo de {MaxComponents} componentes.");
            }

            if (!PackageUrl.TryParse(component.Purl, out var purl) || purl.Version is null)
            {
                skipped++;
                continue;
            }

            if (seen.Add(purl.Coordinates))
            {
                components.Add(new ParsedComponent(purl.Coordinates, component.BomRef, ScopeName(component.Scope)));
            }
        }

        var vex = (bom.Vulnerabilities ?? [])
            .Where(v => v.Analysis is not null && v.Analysis.State != CycloneDX.Models.Vulnerabilities.ImpactAnalysisState.Null && !string.IsNullOrWhiteSpace(v.Id))
            .Select(v => new ParsedVexEntry(
                v.Id.Trim(),
                v.Analysis.State.ToString().ToLowerInvariant(),
                v.Analysis.Justification == CycloneDX.Models.Vulnerabilities.ImpactAnalysisJustification.Null ? null : v.Analysis.Justification.ToString().ToLowerInvariant(),
                (v.Analysis.Response ?? []).Where(r => r != CycloneDX.Models.Vulnerabilities.Response.Null).Select(r => r.ToString().ToLowerInvariant()).ToList(),
                v.Analysis.Detail,
                (v.Affects ?? []).Select(a => a.Ref).Where(r => !string.IsNullOrWhiteSpace(r)).ToList()))
            .ToList();

        return new ParsedBom(specVersion, bom.SerialNumber, bom.Version, components, skipped, vex);
    }

    private static string ReadHeader(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("bomFormat", out var format)
                || format.ValueKind != JsonValueKind.String
                || format.GetString() != "CycloneDX")
            {
                throw new InvalidInputException("No es un documento CycloneDX (bomFormat debe ser \"CycloneDX\").");
            }

            var spec = root.TryGetProperty("specVersion", out var version) && version.ValueKind == JsonValueKind.String ? version.GetString() : null;
            if (spec is null || !Supported.ContainsKey(spec))
            {
                throw new InvalidInputException($"Versión de CycloneDX no soportada: '{spec}'. Se admiten 1.4, 1.5, 1.6 y 1.7.");
            }

            return spec;
        }
        catch (JsonException ex)
        {
            throw new InvalidInputException("El archivo no es JSON válido o supera la profundidad máxima.", ex);
        }
    }

    private static IEnumerable<Component> Flatten(IEnumerable<Component>? components)
    {
        var stack = new Stack<Component>((components ?? []).Reverse());
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            yield return current;
            foreach (var child in (current.Components ?? []).AsEnumerable().Reverse())
            {
                stack.Push(child);
            }
        }
    }

    private static string? ScopeName(Component.ComponentScope? scope) => scope switch
    {
        Component.ComponentScope.Required => "required",
        Component.ComponentScope.Optional => "optional",
        Component.ComponentScope.Excluded => "excluded",
        _ => null,
    };
}
