using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace VulnManager.Infrastructure.Persistence;

/// <summary>Used only by "dotnet ef" to build the model and generate migrations; it never opens a connection.</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<VulnManagerDbContext>
{
    public VulnManagerDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__Default")
                               ?? "Host=localhost;Database=vulnmanager_design";
        var options = new DbContextOptionsBuilder<VulnManagerDbContext>()
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention()
            .Options;
        return new VulnManagerDbContext(options);
    }
}
