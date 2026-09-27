namespace VulnManager.Web.Components;

/// <summary>
/// Runs an application service in its own DI scope. Blazor Server circuits are long-lived, so resolving scoped services
/// (and their DbContext) per operation avoids concurrent use of a single DbContext.
/// </summary>
public sealed class UiRunner(IServiceScopeFactory scopes)
{
    public async Task<TResult> RunAsync<TService, TResult>(Func<TService, Task<TResult>> operation)
        where TService : notnull
    {
        ArgumentNullException.ThrowIfNull(operation);
        await using var scope = scopes.CreateAsyncScope();
        return await operation(scope.ServiceProvider.GetRequiredService<TService>());
    }

    public async Task RunAsync<TService>(Func<TService, Task> operation)
        where TService : notnull
    {
        ArgumentNullException.ThrowIfNull(operation);
        await using var scope = scopes.CreateAsyncScope();
        await operation(scope.ServiceProvider.GetRequiredService<TService>());
    }
}
