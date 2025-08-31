using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface ISmsService
    {
        Task<bool> SendSmsAsync(string phoneNumber, string message);
        Task<bool> SendBulkSmsAsync(List<string> phoneNumbers, string message);
        Task<bool> SendOtpSmsAsync(string phoneNumber, string otpCode);
        Task<bool> SendSecurityAlertSmsAsync(string phoneNumber, string alertMessage);
        Task<bool> SendTwoFactorCodeSmsAsync(string phoneNumber, string code);
        Task<bool> VerifyPhoneNumberAsync(string phoneNumber);
        Task<string> GenerateOtpAsync(string phoneNumber);
        Task<bool> ValidateOtpAsync(string phoneNumber, string otpCode);
        Task<Dictionary<string, object>> GetSmsStatisticsAsync();
        Task<decimal> GetSmsBalanceAsync();
        Task<List<object>> GetSmsHistoryAsync(string phoneNumber);
        Task<bool> BlacklistPhoneNumberAsync(string phoneNumber, string reason);
    }
}