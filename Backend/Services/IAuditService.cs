using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Security.Models;

namespace SabaFone.Backend.Services
{
    public interface IAuditService
    {
        Task<AuditLog> LogAsync(string action, string details, Guid? userId = null);
        Task<AuditLog> LogSecurityEventAsync(string eventType, string details, string severity);
        Task<List<AuditLog>> GetAuditLogsAsync(DateTime? startDate = null, DateTime? endDate = null);
        Task<List<AuditLog>> GetUserAuditLogsAsync(Guid userId);
        Task<List<AuditLog>> GetAuditLogsByActionAsync(string action);
        Task<bool> DeleteOldAuditLogsAsync(int daysToKeep);
        Task<byte[]> ExportAuditLogsAsync(DateTime startDate, DateTime endDate, string format = "csv");
        Task<Dictionary<string, int>> GetAuditStatisticsAsync();
        Task<bool> ArchiveAuditLogsAsync(DateTime beforeDate);
        Task<List<AuditLog>> SearchAuditLogsAsync(string searchTerm);
    }
}