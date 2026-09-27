namespace VulnManager.Application.Security;

public static class AppRoles
{
    /// <summary>Everything, including rules, users and ingestion keys.</summary>
    public const string Admin = "Admin";

    /// <summary>Imports SBOMs, triages findings and manages VEX.</summary>
    public const string Analyst = "Analyst";

    /// <summary>Read-only access and CSV export.</summary>
    public const string Viewer = "Viewer";

    public static IReadOnlyList<string> All { get; } = [Admin, Analyst, Viewer];
}

public static class AppPolicies
{
    public const string CanTriage = "CanTriage";
    public const string CanAdminister = "CanAdminister";
    public const string CanIngest = "CanIngest";
}
