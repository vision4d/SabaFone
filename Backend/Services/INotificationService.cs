using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface INotificationService
    {
        // General Notifications
        Task<bool> SendNotificationAsync(Guid userId, string title, string message, string type = "info");
        Task<bool> SendBroadcastNotificationAsync(string title, string message, string type = "info");
        Task<bool> SendRoleBasedNotificationAsync(string role, string title, string message);
        
        // Security Notifications
        Task<bool> SendSecurityAlertAsync(string severity, string message);
        Task<bool> SendCriticalVulnerabilityAlertAsync(object vulnerability);
        Task<bool> SendHighRiskAlertAsync(object vulnerability, object assessment);
        Task<bool> SendIncidentNotificationAsync(Guid incidentId, string severity, string description);
        
        // System Notifications
        Task<bool> SendSystemMaintenanceNotificationAsync(DateTime scheduledTime, int durationMinutes);
        Task<bool> SendBackupCompletionNotificationAsync(Guid backupId, bool success);
        Task<bool> SendRestoreApprovalRequestAsync(object restore);
        Task<bool> SendAuditScheduledNotificationAsync(object audit);
        
        // User Notifications
        Task<bool> SendPasswordExpiryNotificationAsync(Guid userId, int daysRemaining);
        Task<bool> SendAccountActivityNotificationAsync(Guid userId, string activity);
        Task<bool> SendLoginAlertAsync(Guid userId, string ipAddress, string location);
        
        // Management
        Task<List<object>> GetUserNotificationsAsync(Guid userId, bool unreadOnly = false);
        Task<bool> MarkNotificationAsReadAsync(Guid notificationId);
        Task<bool> DeleteNotificationAsync(Guid notificationId);
        Task<Dictionary<string, object>> GetNotificationStatisticsAsync();
    }
}