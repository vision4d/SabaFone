using System;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Services
{
    public interface IAuthService
    {
        Task<(bool Success, User User, string Error)> AuthenticateAsync(string username, string password);
        Task<(string Token, string RefreshToken, int ExpiresIn)> GenerateTokenAsync(User user);
        Task<bool> ValidateMfaCodeAsync(Guid userId, string code);
        Task<(string Secret, string QrCode, string[] BackupCodes)> EnableMfaAsync(Guid userId);
        Task DisableMfaAsync(Guid userId);
        Task<(bool Success, string Token, string RefreshToken, int ExpiresIn, Guid UserId)> RefreshTokenAsync(string refreshToken);
        Task RevokeTokenAsync(string token);
        Task ChangePasswordAsync(Guid userId, string newPassword);
        Task<string> GeneratePasswordResetTokenAsync(Guid userId);
        Task<(bool Success, string Error, Guid UserId)> ResetPasswordAsync(string token, string newPassword);
        Task<bool> ValidateTokenAsync(string token);
        Task<object[]> GetActiveSessionsAsync(Guid userId);
        Task RevokeSessionAsync(Guid sessionId, Guid userId);
        Task<string> GenerateMfaTokenAsync(Guid userId);
    }
}