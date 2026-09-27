using Microsoft.AspNetCore.Identity;

namespace VulnManager.Infrastructure.Identity;

/// <summary>Application user. Only the e-mail is stored as personal data (LOPDP data minimization).</summary>
public sealed class AppUser : IdentityUser
{
    public DateTimeOffset CreatedAt { get; set; }
}
