using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IEmailService
    {
        Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = true);
        Task<bool> SendEmailAsync(List<string> to, string subject, string body, bool isHtml = true);
        Task<bool> SendEmailWithAttachmentAsync(string to, string subject, string body, byte[] attachment, string fileName);
        Task<bool> SendTemplatedEmailAsync(string to, string templateName, Dictionary<string, object> parameters);
        Task<bool> SendSecurityAlertEmailAsync(string to, string alertType, string message);
        Task<bool> SendPasswordResetEmailAsync(string to, string resetToken);
        Task<bool> SendTwoFactorCodeEmailAsync(string to, string code);
        Task<bool> SendWelcomeEmailAsync(string to, string username);
        Task<bool> SendAccountLockedEmailAsync(string to, string reason);
        Task<bool> QueueEmailAsync(string to, string subject, string body, DateTime? scheduledTime = null);
        Task<bool> SendBulkEmailAsync(List<string> recipients, string subject, string body);
        Task<Dictionary<string, object>> GetEmailStatisticsAsync();
    }
}