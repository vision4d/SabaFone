using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Users.Models;

namespace SabaFone.Backend.Services
{
    public interface IUserService
    {
        Task<User> GetUserByIdAsync(Guid userId);
        Task<User> GetUserByUsernameAsync(string username);
        Task<User> GetUserByEmailAsync(string email);
        Task<IEnumerable<User>> GetUsersAsync(string search, string role, bool? isActive, int page, int pageSize);
        Task<User> CreateUserAsync(User user);
        Task UpdateUserAsync(User user);
        Task DeleteUserAsync(Guid userId);
        Task<bool> LockUserAsync(Guid userId, string reason);
        Task<bool> UnlockUserAsync(Guid userId);
        Task<List<string>> GetUserPermissionsAsync(Guid userId);
        Task<object[]> GetUserActivityAsync(Guid userId, int days);
    }
}