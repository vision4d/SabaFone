using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace SabaFone.Backend.Services.Implementation
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUsername;
        private readonly string _smtpPassword;
        private readonly string _fromEmail;
        private readonly string _fromName;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            _smtpHost = _configuration["Email:SmtpHost"];
            _smtpPort = int.Parse(_configuration["Email:SmtpPort"]);
            _smtpUsername = _configuration["Email:SmtpUsername"];
            _smtpPassword = _configuration["Email:SmtpPassword"];
            _fromEmail = _configuration["Email:FromEmail"];
            _fromName = _configuration["Email:FromName"];
        }

        public async Task<bool> SendEmailAsync(string to, string subject, string body, bool isHtml = true)
        {
            return await SendEmailAsync(new List<string> { to }, subject, body, isHtml);
        }

        public async Task<bool> SendEmailAsync(List<string> to, string subject, string body, bool isHtml = true)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_fromName, _fromEmail));
                
                foreach (var recipient in to)
                {
                    message.To.Add(MailboxAddress.Parse(recipient));
                }

                message.Subject = subject;

                var builder = new BodyBuilder();
                if (isHtml)
                    builder.HtmlBody = body;
                else
                    builder.TextBody = body;

                message.Body = builder.ToMessageBody();

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_smtpHost, _smtpPort, SecureSocketOptions.StartTls);
                    await client.AuthenticateAsync(_smtpUsername, _smtpPassword);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }

                _logger.LogInformation($"Email sent successfully to {string.Join(", ", to)}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending email to {string.Join(", ", to)}");
                return false;
            }
        }

        public async Task<bool> SendEmailWithAttachmentAsync(string to, string subject, string body, byte[] attachment, string fileName)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_fromName, _fromEmail));
                message.To.Add(MailboxAddress.Parse(to));
                message.Subject = subject;

                var builder = new BodyBuilder();
                builder.HtmlBody = body;
                builder.Attachments.Add(fileName, attachment);

                message.Body = builder.ToMessageBody();

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_smtpHost, _smtpPort, SecureSocketOptions.StartTls);
                    await client.AuthenticateAsync(_smtpUsername, _smtpPassword);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending email with attachment to {to}");
                return false;
            }
        }

        public async Task<bool> SendTemplatedEmailAsync(string to, string templateName, Dictionary<string, object> parameters)
        {
            try
            {
                var template = await LoadEmailTemplate(templateName);
                var body = ProcessTemplate(template, parameters);
                return await SendEmailAsync(to, GetTemplateSubject(templateName), body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending templated email to {to}");
                return false;
            }
        }

        public async Task<bool> SendSecurityAlertEmailAsync(string to, string alertType, string message)
        {
            var subject = $"[Security Alert] {alertType}";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2 style='color: #d32f2f;'>Security Alert</h2>
                    <p><strong>Alert Type:</strong> {alertType}</p>
                    <p><strong>Message:</strong> {message}</p>
                    <p><strong>Time:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
                    <hr>
                    <p style='color: #666; font-size: 12px;'>This is an automated security alert from SabaFone SSAS.</p>
                </body>
                </html>";

            return await SendEmailAsync(to, subject, body);
        }

        public async Task<bool> SendPasswordResetEmailAsync(string to, string resetToken)
        {
            var resetUrl = $"{_configuration["AppUrl"]}/reset-password?token={resetToken}";
            var subject = "Password Reset Request";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Password Reset Request</h2>
                    <p>You have requested to reset your password. Click the link below to proceed:</p>
                    <p><a href='{resetUrl}' style='background-color: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Reset Password</a></p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <p>This link will expire in 1 hour.</p>
                </body>
                </html>";

            return await SendEmailAsync(to, subject, body);
        }

        public async Task<bool> SendTwoFactorCodeEmailAsync(string to, string code)
        {
            var subject = "Your Two-Factor Authentication Code";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Two-Factor Authentication</h2>
                    <p>Your verification code is:</p>
                    <h1 style='color: #2196F3; letter-spacing: 5px;'>{code}</h1>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you didn't request this code, please contact support immediately.</p>
                </body>
                </html>";

            return await SendEmailAsync(to, subject, body);
        }

        public async Task<bool> SendWelcomeEmailAsync(string to, string username)
        {
            var subject = "Welcome to SabaFone SSAS";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2>Welcome to SabaFone Security System, {username}!</h2>
                    <p>Your account has been successfully created.</p>
                    <p>You can now log in and start using our security management system.</p>
                    <p>If you have any questions, please contact our support team.</p>
                    <br>
                    <p>Best regards,<br>SabaFone Security Team</p>
                </body>
                </html>";

            return await SendEmailAsync(to, subject, body);
        }

        public async Task<bool> SendAccountLockedEmailAsync(string to, string reason)
        {
            var subject = "Account Security Alert - Account Locked";
            var body = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <h2 style='color: #d32f2f;'>Account Locked</h2>
                    <p>Your account has been locked for security reasons.</p>
                    <p><strong>Reason:</strong> {reason}</p>
                    <p>Please contact your administrator to unlock your account.</p>
                    <p><strong>Time:</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>
                </body>
                </html>";

            return await SendEmailAsync(to, subject, body);
        }

        public async Task<bool> QueueEmailAsync(string to, string subject, string body, DateTime? scheduledTime = null)
        {
            // In a real implementation, this would queue the email for later sending
            // For now, we'll send immediately if no scheduled time, or log for later
            if (!scheduledTime.HasValue || scheduledTime.Value <= DateTime.UtcNow)
            {
                return await SendEmailAsync(to, subject, body);
            }

            _logger.LogInformation($"Email queued for {to} at {scheduledTime}");
            return true;
        }

        public async Task<bool> SendBulkEmailAsync(List<string> recipients, string subject, string body)
        {
            var successCount = 0;
            var failureCount = 0;

            foreach (var batch in recipients.Chunk(50)) // Send in batches of 50
            {
                try
                {
                    await SendEmailAsync(batch.ToList(), subject, body);
                    successCount += batch.Count();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error sending bulk email to batch");
                    failureCount += batch.Count();
                }

                await Task.Delay(1000); // Delay between batches
            }

            _logger.LogInformation($"Bulk email sent: {successCount} success, {failureCount} failures");
            return failureCount == 0;
        }

        public async Task<Dictionary<string, object>> GetEmailStatisticsAsync()
        {
            // In a real implementation, this would fetch from a database
            var stats = new Dictionary<string, object>
            {
                ["TotalSent"] = 1234,
                ["TotalFailed"] = 12,
                ["TodaySent"] = 45,
                ["PendingQueue"] = 3,
                ["SuccessRate"] = 99.0
            };

            return await Task.FromResult(stats);
        }

        private async Task<string> LoadEmailTemplate(string templateName)
        {
            var templatePath = Path.Combine("EmailTemplates", $"{templateName}.html");
            if (File.Exists(templatePath))
            {
                return await File.ReadAllTextAsync(templatePath);
            }
            return string.Empty;
        }

        private string ProcessTemplate(string template, Dictionary<string, object> parameters)
        {
            foreach (var param in parameters)
            {
                template = template.Replace($"{{{{{param.Key}}}}}", param.Value?.ToString());
            }
            return template;
        }

        private string GetTemplateSubject(string templateName)
        {
            var subjects = new Dictionary<string, string>
            {
                ["welcome"] = "Welcome to SabaFone SSAS",
                ["password-reset"] = "Password Reset Request",
                ["security-alert"] = "Security Alert",
                ["account-locked"] = "Account Locked"
            };

            return subjects.ContainsKey(templateName) ? subjects[templateName] : "SabaFone SSAS Notification";
        }
    }
}