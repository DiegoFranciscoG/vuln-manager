using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Serilog;
using Serilog.Formatting.Compact;
using VulnManager.Application;
using VulnManager.Application.Common;
using VulnManager.Infrastructure;
using VulnManager.Infrastructure.Persistence;
using VulnManager.Web;
using VulnManager.Web.Components;
using VulnManager.Web.Controllers;
using VulnManager.Web.ErrorHandling;
using VulnManager.Web.OpenApi;
using VulnManager.Web.Security;
using VulnManager.Web.Seeding;

if (args is [HealthProbe.Argument, ..])
{
    return await HealthProbe.RunAsync();
}

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, logger) => logger
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console(new RenderedCompactJsonFormatter()));

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 11 * 1024 * 1024;
});

builder.Services
    .AddApplication(builder.Configuration)
    .AddInfrastructure(builder.Configuration)
    .AddWebSecurity(builder.Configuration, builder.Environment);

builder.Services.Configure<SyncTriggerOptions>(builder.Configuration.GetSection(SyncTriggerOptions.Section));
builder.Services.AddDataProtection().PersistKeysToDbContext<VulnManagerDbContext>().SetApplicationName("vuln-manager");

builder.Services.AddControllers().AddJsonOptions(options =>
{
    var shared = AppJson.Options;
    options.JsonSerializerOptions.DefaultIgnoreCondition = shared.DefaultIgnoreCondition;
    foreach (var converter in shared.Converters)
    {
        options.JsonSerializerOptions.Converters.Add(converter);
    }
});
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddOpenApi("v1", options => options.AddDocumentTransformer<SecuritySchemesTransformer>());

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddSingleton<UiRunner>();
builder.Services.AddScoped<DemoDataSeeder>();

builder.Services.AddHealthChecks().AddDbContextCheck<VulnManagerDbContext>("database", tags: ["ready"]);

if (builder.Configuration.GetValue("ForwardedHeaders:Enabled", false))
{
    // Render terminates TLS at its proxy; trust exactly one hop of X-Forwarded-For/Proto.
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = 1;
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Clear();
    });
}

var app = builder.Build();

await app.InitializeDatabaseAsync();

if (app.Configuration.GetValue("ForwardedHeaders:Enabled", false))
{
    app.UseForwardedHeaders();
}

app.UseExceptionHandler("/Error", createScopeForErrors: true);
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseSerilogRequestLogging();
// Friendly status pages only for the UI; API clients get the raw status code (401/403/404/429).
app.UseWhen(
    context => !context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase),
    ui => ui.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));

app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/v1.json", "vuln-manager v1");
    options.RoutePrefix = "swagger";
    options.DocumentTitle = "vuln-manager API";
});

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets().AllowAnonymous();
app.MapControllers();
app.MapOpenApi("/openapi/{documentName}.json").AllowAnonymous();
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous().DisableRateLimiting();
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") }).AllowAnonymous().DisableRateLimiting();
app.MapPost("/logout", async (Microsoft.AspNetCore.Identity.SignInManager<VulnManager.Infrastructure.Identity.AppUser> signIn, IAntiforgery antiforgery, HttpContext context) =>
{
    await antiforgery.ValidateRequestAsync(context);
    await signIn.SignOutAsync();
    return Results.LocalRedirect("/login");
}).DisableAntiforgery();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

await app.RunAsync();
return 0;

/// <summary>Entry point, exposed for WebApplicationFactory in the integration tests.</summary>
public partial class Program;
