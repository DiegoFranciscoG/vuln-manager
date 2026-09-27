using Microsoft.AspNetCore.Identity;
using VulnManager.Infrastructure.Identity;

namespace VulnManager.UnitTests.Infrastructure;

public class Argon2idPasswordHasherTests
{
    private readonly Argon2idPasswordHasher _hasher = new();
    private readonly AppUser _user = new() { UserName = "analyst@vulnmanager.test" };

    [Fact]
    public void Hash_uses_the_OWASP_minimum_parameters_and_a_random_salt()
    {
        var first = _hasher.HashPassword(_user, "S3gura!Contraseña");
        var second = _hasher.HashPassword(_user, "S3gura!Contraseña");

        first.Should().StartWith("argon2id$v=19$m=19456,t=2,p=1$");
        first.Should().NotBe(second);
    }

    [Fact]
    public void Verify_accepts_the_right_password_and_rejects_others()
    {
        var hash = _hasher.HashPassword(_user, "S3gura!Contraseña");

        _hasher.VerifyHashedPassword(_user, hash, "S3gura!Contraseña").Should().Be(PasswordVerificationResult.Success);
        _hasher.VerifyHashedPassword(_user, hash, "s3gura!contraseña").Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Weaker_parameters_trigger_a_rehash()
    {
        var hash = _hasher.HashPassword(_user, "S3gura!Contraseña").Replace("m=19456,t=2,p=1", "m=8192,t=1,p=1", StringComparison.Ordinal);
        var parts = hash.Split('$');
        var weaker = new Konscious.Security.Cryptography.Argon2id(System.Text.Encoding.UTF8.GetBytes("S3gura!Contraseña"))
        {
            Salt = Convert.FromBase64String(parts[3]),
            MemorySize = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        };
        parts[4] = Convert.ToBase64String(weaker.GetBytes(32));
        weaker.Dispose();

        _hasher.VerifyHashedPassword(_user, string.Join('$', parts), "S3gura!Contraseña").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void Legacy_identity_hashes_are_accepted_once_and_marked_for_rehash()
    {
        var legacy = new PasswordHasher<AppUser>().HashPassword(_user, "S3gura!Contraseña");

        _hasher.VerifyHashedPassword(_user, legacy, "S3gura!Contraseña").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Theory]
    [InlineData("argon2id$v=19$m=19456,t=2,p=1$notbase64$@@@")]
    [InlineData("argon2id$v=19$m=abc$AAAA$AAAA")]
    [InlineData("argon2id$broken")]
    public void Malformed_hashes_fail_closed(string stored)
    {
        _hasher.VerifyHashedPassword(_user, stored, "x").Should().Be(PasswordVerificationResult.Failed);
    }
}
