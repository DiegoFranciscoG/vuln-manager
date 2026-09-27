using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using VulnManager.Application.Common;
using VulnManager.Application.Services;
using VulnManager.Domain.Entities;

namespace VulnManager.Web.Security;

public static class VmClaims
{
    public const string ActorType = "vm:actor_type";
    public const string ProjectScope = "vm:project";
}

public static class ApiKeyDefaults
{
    public const string Scheme = "ApiKey";
    public const string HeaderName = "X-Api-Key";
}

/// <summary>Authenticates CI pipelines with a project-scoped ingestion key sent in the X-Api-Key header.</summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiKeyService apiKeys) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ApiKeyDefaults.HeaderName, out var values))
        {
            return AuthenticateResult.NoResult();
        }

        var actor = await apiKeys.AuthenticateAsync(values.ToString(), Context.RequestAborted);
        if (actor?.ProjectScope is not { } project)
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, actor.Id),
            new Claim(ClaimTypes.Name, actor.Id),
            new Claim(VmClaims.ActorType, nameof(ActorType.ApiKey)),
            new Claim(VmClaims.ProjectScope, project.ToString("D", CultureInfo.InvariantCulture)),
        ], ApiKeyDefaults.Scheme);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), ApiKeyDefaults.Scheme));
    }
}

public static class ClaimsPrincipalExtensions
{
    /// <summary>Maps the authenticated principal (cookie, JWT or API key) to the application actor.</summary>
    public static Actor ToActor(this ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub")
                 ?? throw new InvalidOperationException("Authenticated principal without an identifier.");

        if (user.FindFirstValue(VmClaims.ActorType) == nameof(ActorType.ApiKey)
            && Guid.TryParse(user.FindFirstValue(VmClaims.ProjectScope), out var project))
        {
            return new Actor(ActorType.ApiKey, id, [], project);
        }

        var roles = user.FindAll(ClaimTypes.Role).Concat(user.FindAll("role")).Select(c => c.Value).Distinct(StringComparer.Ordinal).ToArray();
        return new Actor(ActorType.User, id, roles);
    }
}
