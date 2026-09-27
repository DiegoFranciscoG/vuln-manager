using System.Globalization;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using VulnManager.Application.Security;
using VulnManager.Infrastructure.Identity;
using VulnManager.Infrastructure.Persistence;

namespace VulnManager.Web.Security;

public static class RateLimitPolicies
{
    public const string Login = "login";
    public const string Ingest = "ingest";
    public const string SyncTrigger = "sync-trigger";
}

public static class SecurityServiceCollectionExtensions
{
    private const string SmartScheme = "smart";

    public static IServiceCollection AddWebSecurity(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        services.AddOptions<JwtOptions>().Bind(configuration.GetSection(JwtOptions.Section)).ValidateDataAnnotations().ValidateOnStart();
        services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();
        services.AddSingleton<TokenService>();

        services.AddIdentityCore<AppUser>(options =>
            {
                options.Password.RequiredLength = 12;
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;
                options.User.RequireUniqueEmail = true;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<VulnManagerDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();
        services.Replace(ServiceDescriptor.Scoped<IPasswordHasher<AppUser>, Argon2idPasswordHasher>());

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = SmartScheme;
                options.DefaultChallengeScheme = SmartScheme;
            })
            .AddPolicyScheme(SmartScheme, "Cookie, JWT o clave de API", options => options.ForwardDefaultSelector = SelectScheme)
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { })
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeyDefaults.Scheme, null)
            .AddIdentityCookies();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).Configure<IOptions<JwtOptions>>((bearer, jwt) =>
        {
            var settings = jwt.Value;
            bearer.MapInboundClaims = true;
            bearer.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = settings.Issuer,
                ValidateAudience = true,
                ValidAudience = settings.Audience,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = settings.SigningKey(),
                ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                ClockSkew = TimeSpan.FromSeconds(30),
                RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
            };
        });

        // Production (HTTPS behind Render's proxy): Secure cookies with the __Host- prefix. Local HTTP runs set
        // Security:SecureCookies=false because browsers drop Secure cookies on plain HTTP.
        var secureCookies = configuration.GetValue("Security:SecureCookies", true);
        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.AccessDeniedPath = "/forbidden";
            options.Cookie.Name = secureCookies ? "__Host-vm-auth" : "vm-auth";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = secureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
        });

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(AppPolicies.CanTriage, policy => policy.RequireRole(AppRoles.Admin, AppRoles.Analyst))
            .AddPolicy(AppPolicies.CanAdminister, policy => policy.RequireRole(AppRoles.Admin))
            .AddPolicy(AppPolicies.CanIngest, policy => policy.RequireAssertion(ctx =>
                ctx.User.IsInRole(AppRoles.Admin) || ctx.User.IsInRole(AppRoles.Analyst) || ctx.User.HasClaim(VmClaims.ActorType, "ApiKey")));

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, cancellationToken) =>
            {
                var response = context.HttpContext.Response;
                var seconds = 60;
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
                    response.Headers.RetryAfter = seconds.ToString(NumberFormatInfo.InvariantInfo);
                }

                // Browsers get their own page: re-executing the status page would bounce through the login redirect in a loop.
                if (!context.HttpContext.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
                {
                    response.ContentType = "text/html; charset=utf-8";
                    await response.WriteAsync(TooManyRequestsPage(seconds), cancellationToken);
                }
            };
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                RateLimitPartition.GetFixedWindowLimiter(context.User.Identity?.Name ?? ClientKey(context), _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 600,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                }));
            // Only credential submissions count (OWASP): viewing the login page is never throttled.
            options.AddPolicy(RateLimitPolicies.Login, context => HttpMethods.IsPost(context.Request.Method)
                ? RateLimitPartition.GetFixedWindowLimiter(ClientKey(context), _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0,
                })
                : RateLimitPartition.GetNoLimiter("login-page"));
            options.AddPolicy(RateLimitPolicies.Ingest, context => RateLimitPartition.GetFixedWindowLimiter(context.User.Identity?.Name ?? ClientKey(context), _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
            options.AddPolicy(RateLimitPolicies.SyncTrigger, _ => RateLimitPartition.GetFixedWindowLimiter("sync-trigger", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 6,
                Window = TimeSpan.FromHours(1),
                QueueLimit = 0,
            }));
        });

        var origins = (configuration["Cors:AllowedOrigins"] ?? string.Empty)
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        services.AddCors(options => options.AddDefaultPolicy(policy =>
        {
            if (origins.Length > 0)
            {
                policy.WithOrigins(origins).WithMethods("GET", "POST", "PUT", "DELETE").WithHeaders("Authorization", "Content-Type", ApiKeyDefaults.HeaderName);
            }
        }));

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = secureCookies ? "__Host-vm-af" : "vm-af";
            options.Cookie.SecurePolicy = secureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
        });

        if (!environment.IsDevelopment())
        {
            services.AddHsts(options =>
            {
                options.MaxAge = TimeSpan.FromDays(365);
                options.IncludeSubDomains = true;
            });
        }

        return services;
    }

    private static string? SelectScheme(HttpContext context)
    {
        if (context.Request.Headers.ContainsKey(ApiKeyDefaults.HeaderName))
        {
            return ApiKeyDefaults.Scheme;
        }

        var authorization = context.Request.Headers.Authorization.ToString();
        return authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? JwtBearerDefaults.AuthenticationScheme
            : IdentityConstants.ApplicationScheme;
    }

    /// <summary>Client address as resolved by the forwarded-headers middleware (Render proxy), or a fixed bucket.</summary>
    private static string TooManyRequestsPage(int seconds) => $"""
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Demasiados intentos · vuln-manager</title><link rel="stylesheet" href="/app.css" /></head>
        <body><main class="content"><section class="card"><h1>Demasiados intentos</h1>
        <p>Por seguridad limitamos los intentos seguidos. Espera {seconds} segundos y vuelve a intentarlo.</p>
        <a class="btn" href="/login">Volver al inicio de sesión</a></section></main></body>
        </html>
        """;

    private static string ClientKey(HttpContext context) =>
        context.Connection.RemoteIpAddress is { } ip && !IPAddress.IsLoopback(ip) ? ip.ToString() : "local";
}

/// <summary>Runs <see cref="JwtOptions.Validate"/> at startup so a missing or weak secret stops the app.</summary>
public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var errors = options.Validate(new System.ComponentModel.DataAnnotations.ValidationContext(options)).Select(r => r.ErrorMessage ?? "JWT inválido").ToList();
        return errors.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(errors);
    }
}
