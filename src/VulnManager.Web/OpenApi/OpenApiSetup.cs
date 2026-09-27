using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;
using VulnManager.Web.Security;

namespace VulnManager.Web.OpenApi;

/// <summary>Documents the two API authentication schemes: JWT bearer (users) and X-Api-Key (CI ingestion).</summary>
internal sealed class SecuritySchemesTransformer : IOpenApiDocumentTransformer
{
    public Task TransformAsync(OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(document);
        document.Info = new OpenApiInfo
        {
            Title = "vuln-manager API",
            Version = "v1",
            Description = "Gestión y priorización de vulnerabilidades a partir de SBOM CycloneDX. " +
                          "Autenticación: JWT (POST /api/auth/token) o clave de ingesta por proyecto en la cabecera X-Api-Key. " +
                          "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
            License = new OpenApiLicense { Name = "MIT" },
        };

        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Token de POST /api/auth/token (15 minutos).",
        };
        document.Components.SecuritySchemes[ApiKeyDefaults.Scheme] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.ApiKey,
            In = ParameterLocation.Header,
            Name = ApiKeyDefaults.HeaderName,
            Description = "Clave de ingesta del proyecto (vmk_...). Solo permite cargar SBOM/VEX y leer ese proyecto.",
        };

        document.Security ??= [];
        document.Security.Add(new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("Bearer", document)] = [] });
        document.Security.Add(new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference(ApiKeyDefaults.Scheme, document)] = [] });
        return Task.CompletedTask;
    }
}
