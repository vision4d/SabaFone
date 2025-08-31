using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IRepository<T> where T : class
    {
        // Basic CRUD
        Task<T> GetByIdAsync(Guid id);
        Task<IEnumerable<T>> GetAllAsync();
        Task<T> AddAsync(T entity);
        Task UpdateAsync(T entity);
        Task DeleteAsync(T entity);
        Task<bool> DeleteByIdAsync(Guid id);
        
        // Query
        Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate);
        Task<T> FirstOrDefaultAsync(Expression<Func<T, bool>> predicate);
        Task<bool> AnyAsync(Expression<Func<T, bool>> predicate);
        Task<int> CountAsync(Expression<Func<T, bool>> predicate = null);
        
        // Advanced Query
        IQueryable<T> Query();
        IQueryable<T> QueryNoTracking();
        Task<IEnumerable<T>> GetPagedAsync(int page, int pageSize);
        Task<IEnumerable<T>> GetPagedAsync(int page, int pageSize, Expression<Func<T, bool>> predicate);
        
        // Bulk Operations
        Task<IEnumerable<T>> AddRangeAsync(IEnumerable<T> entities);
        Task UpdateRangeAsync(IEnumerable<T> entities);
        Task DeleteRangeAsync(IEnumerable<T> entities);
        
        // Include
        IQueryable<T> Include(params Expression<Func<T, object>>[] includes);
        
        // Raw SQL
        Task<IEnumerable<T>> FromSqlAsync(string sql, params object[] parameters);
        Task<int> ExecuteSqlAsync(string sql, params object[] parameters);
    }
}