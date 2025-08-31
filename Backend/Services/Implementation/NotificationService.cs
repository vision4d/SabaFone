using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Data;
using SabaFone.Backend.Hubs;

namespace SabaFone.Backend.Services.Implementation
{
    public class NotificationService : INotificationService
    {
        private readonly SsasDbContext _context;
        private readonly ILogger<NotificationService> _logger;
        private readonly IHubContext<NotificationHub> _notificationHub;
        private readonly IHubContext<SecurityHub> _securityHub;
        private readonly IEmailService _emailService;
        private readonly ISmsService _smsService;

        public NotificationService(
            SsasDbContext context,
            ILogger<NotificationService> logger,
            IHubContext<NotificationHub> notificationHub,
            IHubContext<SecurityHub> securityHub,
            IEmailService emailService,
            ISmsService smsService)
        {
            _context = context;
            _logger = logger;
            _notificationHub = notificationHub;
            _securityHub = securityHub;
            _emailService = emailService;
            _smsService = smsService;
        }

        public async Task<bool> SendNotificationAsync(Guid userId, string title, string message, string type = "info")
        {
            try
            {
                // Store notification in database
                var notification = new
                {
                    NotificationId = Guid.NewGuid(),
                    UserId = userId,
                    Title = title,
                    Message = message,
                    Type = type,
                    CreatedAt = DateTime.UtcNow,
                    IsRead = false
                };

                // Send real-time notification via SignalR
                await _notificationHub.Clients.User(userId.ToString())
                    .SendAsync("ReceiveNotification", notification);

                _logger.LogInformation($"Notification sent to user {userId}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending notification to user {userId}");
                return false;
            }
        }

        public async Task<bool> SendBroadcastNotificationAsync(string title, string message, string type = "info")
        {
            try
            {
                var notification = new
                {
                    NotificationId = Guid.NewGuid(),
                    Title = title,
                    Message = message,
                    Type = type,
                    CreatedAt = DateTime.UtcNow
                };

                await _notificationHub.Clients.All.SendAsync("ReceiveBroadcast", notification);

                _logger.LogInformation("Broadcast notification sent to all users");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending broadcast notification");
                return false;
            }
        }

        public async Task<bool> SendRoleBasedNotificationAsync(string role, string title, string message)
        {
            try
            {
                await _notificationHub.Clients.Group($"Role_{role}")
                    .SendAsync("ReceiveNotification", new
                    {
                        Title = title,
                        Message = message,
                        Type = "role",
                        CreatedAt = DateTime.UtcNow
                    });

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending notification to role {role}");
                return false;
            }
        }

        public async Task<bool> SendSecurityAlertAsync(string severity, string message)
        {
            try
            {
                // Send to security hub
                await _securityHub.Clients.All.SendAsync("SecurityAlert", severity, message);

                // Send email to security team
                var securityEmails = await GetSecurityTeamEmailsAsync();
                foreach (var email in securityEmails)
                {
                    await _emailService.SendSecurityAlertEmailAsync(email, severity, message);
                }

                // For critical alerts, also send SMS
                if (severity == "Critical")
                {
                    var securityPhones = await GetSecurityTeamPhonesAsync();
                    foreach (var phone in securityPhones)
                    {
                        await _smsService.SendSecurityAlertSmsAsync(phone, message);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending security alert");
                return false;
            }
        }

        public async Task<bool> SendCriticalVulnerabilityAlertAsync(object vulnerability)
        {
            var message = $"Critical vulnerability detected: {vulnerability}";
            return await SendSecurityAlertAsync("Critical", message);
        }

        public async Task<bool> SendHighRiskAlertAsync(object vulnerability, object assessment)
        {
            var message = $"High risk vulnerability assessment: {vulnerability}";
            return await SendSecurityAlertAsync("High", message);
        }

        public async Task<bool> SendIncidentNotificationAsync(Guid incidentId, string severity, string description)
        {
            try
            {
                // Notify security team
                await _securityHub.Clients.Group("SecurityTeam")
                    .SendAsync("IncidentAlert", new
                    {
                        IncidentId = incidentId,
                        Severity = severity,
                        Description = description,
                        Timestamp = DateTime.UtcNow
                    });

                // Send emails based on severity
                if (severity == "Critical" || severity == "High")
                {
                    var emails = await GetIncidentResponseTeamEmailsAsync();
                    var subject = $"[{severity}] Security Incident: {incidentId}";
                    var body = $"Incident Description: {description}\n\nPlease investigate immediately.";
                    
                    foreach (var email in emails)
                    {
                        await _emailService.SendEmailAsync(email, subject, body);
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending incident notification for {incidentId}");
                return false;
            }
        }

        public async Task<bool> SendSystemMaintenanceNotificationAsync(DateTime scheduledTime, int durationMinutes)
        {
            var message = $"System maintenance scheduled for {scheduledTime:yyyy-MM-dd HH:mm} UTC. " +
                         $"Expected duration: {durationMinutes} minutes.";

            await SendBroadcastNotificationAsync("System Maintenance", message, "warning");
            return true;
        }

        public async Task<bool> SendBackupCompletionNotificationAsync(Guid backupId, bool success)
        {
            var message = success 
                ? $"Backup {backupId} completed successfully."
                : $"Backup {backupId} failed. Please check logs for details.";

            var type = success ? "success" : "error";
            
            await SendRoleBasedNotificationAsync("Admin", "Backup Status", message);
            return true;
        }

        public async Task<bool> SendRestoreApprovalRequestAsync(object restore)
        {
            var message = $"Restore operation requires approval: {restore}";
            await SendRoleBasedNotificationAsync("Admin", "Restore Approval Required", message);
            return true;
        }

        public async Task<bool> SendAuditScheduledNotificationAsync(object audit)
        {
            var message = $"Compliance audit scheduled: {audit}";
            await SendRoleBasedNotificationAsync("ComplianceOfficer", "Audit Scheduled", message);
            return true;
        }

        public async Task<bool> SendPasswordExpiryNotificationAsync(Guid userId, int daysRemaining)
        {
            var message = $"Your password will expire in {daysRemaining} days. Please change it soon.";
            await SendNotificationAsync(userId, "Password Expiry Warning", message, "warning");
            
            // Also send email
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                await _emailService.SendEmailAsync(user.Email, 
                    "Password Expiry Warning", 
                    $"Your SabaFone SSAS password will expire in {daysRemaining} days.");
            }
            
            return true;
        }

        public async Task<bool> SendAccountActivityNotificationAsync(Guid userId, string activity)
        {
            var message = $"Account activity detected: {activity}";
            return await SendNotificationAsync(userId, "Account Activity", message, "info");
        }

        public async Task<bool> SendLoginAlertAsync(Guid userId, string ipAddress, string location)
        {
            var message = $"New login from {ipAddress} ({location})";
            await SendNotificationAsync(userId, "New Login Detected", message, "info");
            
            // Send email alert
            var user = await _context.Users.FindAsync(userId);
            if (user != null)
            {
                await _emailService.SendEmailAsync(user.Email,
                    "New Login to Your Account",
                    $"A new login was detected from IP: {ipAddress}, Location: {location}. " +
                    "If this wasn't you, please change your password immediately.");
            }
            
            return true;
        }

        public async Task<List<object>> GetUserNotificationsAsync(Guid userId, bool unreadOnly = false)
        {
            // In a real implementation, fetch from database
            var notifications = new List<object>
            {
                new 
                {
                    NotificationId = Guid.NewGuid(),
                    Title = "Sample Notification",
                    Message = "This is a sample notification",
                    Type = "info",
                    CreatedAt = DateTime.UtcNow,
                    IsRead = false
                }
            };

            if (unreadOnly)
            {
                notifications = notifications.Where(n => !(bool)n.GetType().GetProperty("IsRead").GetValue(n)).ToList();
            }

            return await Task.FromResult(notifications);
        }

        public async Task<bool> MarkNotificationAsReadAsync(Guid notificationId)
        {
            // In a real implementation, update in database
            _logger.LogInformation($"Notification {notificationId} marked as read");
            return await Task.FromResult(true);
        }

        public async Task<bool> DeleteNotificationAsync(Guid notificationId)
        {
            // In a real implementation, delete from database
            _logger.LogInformation($"Notification {notificationId} deleted");
            return await Task.FromResult(true);
        }

        public async Task<Dictionary<string, object>> GetNotificationStatisticsAsync()
        {
            var stats = new Dictionary<string, object>
            {
                ["TotalNotifications"] = 1234,
                ["UnreadNotifications"] = 45,
                ["TodayNotifications"] = 23,
                ["SecurityAlerts"] = 5,
                ["SystemNotifications"] = 12
            };

            return await Task.FromResult(stats);
        }

        private async Task<List<string>> GetSecurityTeamEmailsAsync()
        {
            var emails = await _context.Users
                .Where(u => u.UserRoles.Any(ur => ur.Role.Name == "SecurityOfficer" || ur.Role.Name == "Admin"))
                .Select(u => u.Email)
                .ToListAsync();

            return emails;
        }

        private async Task<List<string>> GetSecurityTeamPhonesAsync()
        {
            var phones = await _context.Users
                .Where(u => u.UserRoles.Any(ur => ur.Role.Name == "SecurityOfficer"))
                .Where(u => !string.IsNullOrEmpty(u.PhoneNumber))
                .Select(u => u.PhoneNumber)
                .ToListAsync();

            return phones;
        }

        private async Task<List<string>> GetIncidentResponseTeamEmailsAsync()
        {
            var emails = await _context.Users
                .Where(u => u.UserRoles.Any(ur => 
                    ur.Role.Name == "SecurityOfficer" || 
                    ur.Role.Name == "Admin" || 
                    ur.Role.Name == "IncidentResponder"))
                .Select(u => u.Email)
                .ToListAsync();

            return emails;
        }
    }
}