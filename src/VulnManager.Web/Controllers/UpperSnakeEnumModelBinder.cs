using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace VulnManager.Web.Controllers;

/// <summary>
/// Binds enums in query strings and routes with the same names as the JSON contract (UPPER_SNAKE_CASE, e.g.
/// FALSE_POSITIVE or SLA_DUE). Numbers and comma-separated combinations are rejected so only defined names are accepted.
/// </summary>
public sealed class UpperSnakeEnumModelBinderProvider : IModelBinderProvider
{
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.BindingInfo.BindingSource == BindingSource.Body)
        {
            return null;
        }

        var enumType = Nullable.GetUnderlyingType(context.Metadata.ModelType) ?? context.Metadata.ModelType;
        return enumType.IsEnum ? new UpperSnakeEnumModelBinder(enumType) : null;
    }
}

internal sealed class UpperSnakeEnumModelBinder(Type enumType) : IModelBinder
{
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        var result = bindingContext.ValueProvider.GetValue(bindingContext.ModelName);
        if (result == ValueProviderResult.None)
        {
            return Task.CompletedTask;
        }

        bindingContext.ModelState.SetModelValue(bindingContext.ModelName, result);
        var raw = result.FirstValue;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Task.CompletedTask;
        }

        var candidate = raw.Trim().Replace("_", string.Empty, StringComparison.Ordinal);
        var name = Array.Find(Enum.GetNames(enumType), n => string.Equals(n, candidate, StringComparison.OrdinalIgnoreCase));
        if (name is null)
        {
            bindingContext.ModelState.TryAddModelError(bindingContext.ModelName, $"El valor '{raw}' no es válido.");
            return Task.CompletedTask;
        }

        bindingContext.Result = ModelBindingResult.Success(Enum.Parse(enumType, name));
        return Task.CompletedTask;
    }
}
