using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace VulnManager.Infrastructure.Identity;

/// <summary>
/// Argon2id password hashing with the OWASP Password Storage Cheat Sheet minimum (m = 19 MiB, t = 2, p = 1).
/// Format: argon2id$v=19$m=19456,t=2,p=1$salt$hash (base64). Legacy Identity hashes are verified and rehashed.
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher<AppUser>
{
    public const int MemoryKib = 19_456;
    public const int Iterations = 2;
    public const int Parallelism = 1;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const string Prefix = "argon2id$";

    private readonly PasswordHasher<AppUser> _legacy = new();

    public string HashPassword(AppUser user, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Compute(password, salt, MemoryKib, Iterations, Parallelism);
        return string.Create(CultureInfo.InvariantCulture,
            $"{Prefix}v=19$m={MemoryKib},t={Iterations},p={Parallelism}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}");
    }

    public PasswordVerificationResult VerifyHashedPassword(AppUser user, string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(hashedPassword);
        ArgumentNullException.ThrowIfNull(providedPassword);
        if (!hashedPassword.StartsWith(Prefix, StringComparison.Ordinal))
        {
            var legacy = _legacy.VerifyHashedPassword(user, hashedPassword, providedPassword);
            return legacy == PasswordVerificationResult.Failed ? legacy : PasswordVerificationResult.SuccessRehashNeeded;
        }

        var parts = hashedPassword.Split('$');
        if (parts.Length != 5 || !TryParseParameters(parts[2], out var memory, out var iterations, out var parallelism))
        {
            return PasswordVerificationResult.Failed;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expected = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return PasswordVerificationResult.Failed;
        }

        var actual = Compute(providedPassword, salt, memory, iterations, parallelism);
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return PasswordVerificationResult.Failed;
        }

        return memory == MemoryKib && iterations == Iterations && parallelism == Parallelism
            ? PasswordVerificationResult.Success
            : PasswordVerificationResult.SuccessRehashNeeded;
    }

    private static byte[] Compute(string password, byte[] salt, int memory, int iterations, int parallelism)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memory,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon.GetBytes(HashBytes);
    }

    private static bool TryParseParameters(string value, out int memory, out int iterations, out int parallelism)
    {
        memory = iterations = parallelism = 0;
        var pairs = value.Split(',').Select(p => p.Split('=')).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1], StringComparer.Ordinal);
        return pairs.TryGetValue("m", out var m) && int.TryParse(m, NumberStyles.None, CultureInfo.InvariantCulture, out memory) && memory is >= 8 and <= 1_048_576
               && pairs.TryGetValue("t", out var t) && int.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out iterations) && iterations is >= 1 and <= 20
               && pairs.TryGetValue("p", out var p) && int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out parallelism) && parallelism is >= 1 and <= 16;
    }
}
