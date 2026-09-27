using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using VulnManager.Infrastructure.Identity;
using VulnManager.Web.Security;

namespace VulnManager.Web.Controllers;

public sealed class TokenRequest
{
    [Required]
    [EmailAddress]
    [StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(128, MinimumLength = 1)]
    public string Password { get; set; } = string.Empty;
}

/// <summary>Issues short-lived JWTs for API clients. Rate limited per client address; Identity lockout applies.</summary>
[ApiController]
[Route("api/auth")]
[Produces("application/json")]
public sealed class AuthController(UserManager<AppUser> users, SignInManager<AppUser> signIn, TokenService tokens) : ControllerBase
{
    /// <summary>Exchanges e-mail and password for a 15-minute access token.</summary>
    [HttpPost("token")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitPolicies.Login)]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<IActionResult> Token([FromBody] TokenRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var user = await users.FindByEmailAsync(request.Email);
        if (user is null)
        {
            return Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Credenciales inválidas");
        }

        var result = await signIn.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            return Problem(statusCode: StatusCodes.Status401Unauthorized, title: result.IsLockedOut ? "Cuenta bloqueada temporalmente" : "Credenciales inválidas");
        }

        return Ok(tokens.Issue(user.Id, await users.GetRolesAsync(user)));
    }
}
