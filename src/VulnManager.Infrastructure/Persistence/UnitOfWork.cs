using Microsoft.EntityFrameworkCore;
using Npgsql;
using VulnManager.Application.Abstractions.Persistence;
using VulnManager.Application.Exceptions;

namespace VulnManager.Infrastructure.Persistence;

public sealed class UnitOfWork(VulnManagerDbContext db) : IUnitOfWork
{
    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            throw new ConflictException("El registro fue modificado por otra persona. Recarga e inténtalo de nuevo.", ex);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            throw new ConflictException("El registro ya existe.", ex);
        }
    }

    internal static bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
}
