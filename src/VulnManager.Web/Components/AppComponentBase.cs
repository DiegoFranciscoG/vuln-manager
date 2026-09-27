using System.Globalization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using VulnManager.Application.Common;
using VulnManager.Application.Exceptions;
using VulnManager.Domain.Common;
using VulnManager.Web.Security;

namespace VulnManager.Web.Components;

/// <summary>Base for interactive pages: resolves the actor and turns application errors into a visible message.</summary>
public abstract class AppComponentBase : ComponentBase
{
    [CascadingParameter]
    protected Task<AuthenticationState> AuthenticationState { get; set; } = default!;

    [Inject]
    protected UiRunner Ui { get; set; } = default!;

    protected string? ErrorMessage { get; set; }

    protected string? SuccessMessage { get; set; }

    protected bool Busy { get; set; }

    protected async Task<Actor> ActorAsync() => (await AuthenticationState).User.ToActor();

    protected async Task<bool> TryAsync(Func<Task> action, string? success = null)
    {
        ArgumentNullException.ThrowIfNull(action);
        ErrorMessage = null;
        SuccessMessage = null;
        Busy = true;
        try
        {
            await action();
            SuccessMessage = success;
            return true;
        }
        catch (AppException ex)
        {
            ErrorMessage = ex.Message;
            return false;
        }
        catch (DomainException ex)
        {
            ErrorMessage = ex.Message;
            return false;
        }
        finally
        {
            Busy = false;
        }
    }

    protected static string Date(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) ?? "—";

    protected static string Day(DateTimeOffset? value) =>
        value?.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";

    protected static string Percent(decimal? value) =>
        value is null ? "—" : (value.Value * 100).ToString("0.##", CultureInfo.InvariantCulture) + " %";

    protected static string Number(decimal? value, string format = "0.0") =>
        value?.ToString(format, CultureInfo.InvariantCulture) ?? "—";
}
