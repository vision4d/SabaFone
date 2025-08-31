using System;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IUnitOfWork : IDisposable
    {
        // Repositories
        IRepository<T> Repository<T>() where T : class;

        // Transaction Management
        Task<int> SaveChangesAsync();
        Task BeginTransactionAsync();
        Task CommitTransactionAsync();
        Task RollbackTransactionAsync();

        // Database Operations
        Task<bool> EnsureDatabaseCreatedAsync();
        Task<bool> EnsureDatabaseDeletedAsync();
        Task MigrateAsync();

        // Raw Queries
        Task<int> ExecuteSqlCommandAsync(string sql, params object[] parameters);

        // Dispose Pattern
        //void Dispose();
        new void Dispose();
        
    }
}