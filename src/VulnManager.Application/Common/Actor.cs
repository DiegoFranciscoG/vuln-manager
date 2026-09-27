using VulnManager.Application.Security;
using VulnManager.Domain.Entities;

namespace VulnManager.Application.Common;

/// <summary>Who performs an action. <see cref="Id"/> is a user id, an API key prefix or "system"; never an e-mail.</summary>
public sealed record Actor(ActorType Type, string Id, IReadOnlyCollection<string> Roles, Guid? ProjectScope = null)
{
    public static Actor System { get; } = new(ActorType.System, Finding.SystemActor, []);

    public bool IsAdmin => Roles.Contains(AppRoles.Admin);

    public bool CanTriage => Roles.Contains(AppRoles.Admin) || Roles.Contains(AppRoles.Analyst);

    /// <summary>An API key actor is restricted to its own project (OWASP API1:2023 BOLA).</summary>
    public bool CanAccessProject(Guid projectId) => ProjectScope is null || ProjectScope == projectId;
}

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int Total)
{
    public int TotalPages => PageSize == 0 ? 0 : (int)Math.Ceiling(Total / (double)PageSize);
}
