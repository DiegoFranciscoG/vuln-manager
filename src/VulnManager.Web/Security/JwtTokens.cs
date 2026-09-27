using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace VulnManager.Web.Security;

/// <summary>JWT settings. The secret has no default: the app refuses to start without a 256-bit (32-byte) secret.</summary>
public sealed class JwtOptions : IValidatableObject
{
    public const string Section = "Jwt";
    public const int MinimumSecretBytes = 32;

    public string Secret { get; set; } = string.Empty;

    [Required]
    public string Issuer { get; set; } = "vuln-manager";

    [Required]
    public string Audience { get; set; } = "vuln-manager-api";

    [Range(1, 60)]
    public int LifetimeMinutes { get; set; } = 15;

    public SymmetricSecurityKey SigningKey() => new(Encoding.UTF8.GetBytes(Secret));

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Encoding.UTF8.GetByteCount(Secret ?? string.Empty) < MinimumSecretBytes)
        {
            yield return new ValidationResult($"Define Jwt__Secret (JWT_SECRET) con al menos {MinimumSecretBytes} bytes aleatorios (256 bits).", [nameof(Secret)]);
        }
    }
}

public sealed record TokenResponse(string AccessToken, string TokenType, int ExpiresIn);

/// <summary>Issues short-lived HS256 access tokens for API clients (Swagger, scripts).</summary>
public sealed class TokenService(IOptions<JwtOptions> options, TimeProvider time)
{
    private readonly JsonWebTokenHandler _handler = new();

    public TokenResponse Issue(string userId, IEnumerable<string> roles)
    {
        var settings = options.Value;
        var now = time.GetUtcNow().UtcDateTime;
        var claims = new List<Claim> { new(JwtRegisteredClaimNames.Sub, userId) };
        claims.AddRange(roles.Select(r => new Claim("role", r)));

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = settings.Issuer,
            Audience = settings.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(settings.LifetimeMinutes),
            SigningCredentials = new SigningCredentials(settings.SigningKey(), SecurityAlgorithms.HmacSha256),
        });
        return new TokenResponse(token, "Bearer", settings.LifetimeMinutes * 60);
    }
}
