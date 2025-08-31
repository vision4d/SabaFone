using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Security.Models;

namespace SabaFone.Backend.Services.Implementation
{
    public class AuditService : IAuditService
    {
        private readonly SsasDbContext _context;
        private readonly ILogger<AuditService> _logger;

        public AuditService(SsasDbContext context, ILogger<AuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<AuditLog> LogAsync(string action, string details, Guid? userId = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    AuditId = Guid.NewGuid(),
                    Action = action,
                    Details = details,
                    UserId = userId,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = GetClientIpAddress(),
                    UserAgent = GetUserAgent()
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                return auditLog;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating audit log");
                throw;
            }
        }

        public async Task<AuditLog> LogSecurityEventAsync(string eventType, string details, string severity)
        {
            var auditLog = new AuditLog
            {
                AuditId = Guid.NewGuid(),
                Action = $"SECURITY_{eventType}",
                Details = details,
                Severity = severity,
                Timestamp = DateTime.UtcNow,
                Category = "Security"
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();

            return auditLog;
        }

        public async Task<List<AuditLog>> GetAuditLogsAsync(DateTime? startDate = null, DateTime? endDate = null)
        {
            var query = _context.AuditLogs.AsQueryable();

            if (startDate.HasValue)
                query = query.Where(a => a.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(a => a.Timestamp <= endDate.Value);

            return await query
                .OrderByDescending(a => a.Timestamp)
                .ToListAsync();
        }

        public async Task<List<AuditLog>> GetUserAuditLogsAsync(Guid userId)
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.Timestamp)
                .ToListAsync();
        }

        public async Task<List<AuditLog>> GetAuditLogsByActionAsync(string action)
        {
            return await _context.AuditLogs
                .Where(a => a.Action == action)
                .OrderByDescending(a => a.Timestamp)
                .ToListAsync();
        }

        public async Task<bool> DeleteOldAuditLogsAsync(int daysToKeep)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-daysToKeep);
                var oldLogs = await _context.AuditLogs
                    .Where(a => a.Timestamp < cutoffDate)
                    .ToListAsync();

                if (oldLogs.Any())
                {
                    // Archive before deleting
                    await ArchiveAuditLogsAsync(cutoffDate);

                    _context.AuditLogs.RemoveRange(oldLogs);
                    await _context.SaveChangesAsync();

                    _logger.LogInformation($"Deleted {oldLogs.Count} audit logs older than {daysToKeep} days");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting old audit logs");
                return false;
            }
        }

        public async Task<byte[]> ExportAuditLogsAsync(DateTime startDate, DateTime endDate, string format = "csv")
        {
            var logs = await GetAuditLogsAsync(startDate, endDate);

            if (format.ToLower() == "csv")
            {
                return ExportToCsv(logs);
            }
            else if (format.ToLower() == "json")
            {
                return ExportToJson(logs);
            }
            else
            {
                throw new NotSupportedException($"Export format '{format}' is not supported");
            }
        }

        public async Task<Dictionary<string, int>> GetAuditStatisticsAsync()
        {
            var stats = new Dictionary<string, int>();

            var today = DateTime.UtcNow.Date;
            var thisWeek = today.AddDays(-7);
            var thisMonth = today.AddDays(-30);

            stats["TotalLogs"] = await _context.AuditLogs.CountAsync();
            stats["LogsToday"] = await _context.AuditLogs.CountAsync(a => a.Timestamp >= today);
            stats["LogsThisWeek"] = await _context.AuditLogs.CountAsync(a => a.Timestamp >= thisWeek);
            stats["LogsThisMonth"] = await _context.AuditLogs.CountAsync(a => a.Timestamp >= thisMonth);
            stats["SecurityEvents"] = await _context.AuditLogs.CountAsync(a => a.Category == "Security");
            stats["UserActions"] = await _context.AuditLogs.CountAsync(a => a.UserId != null);

            return stats;
        }

        public async Task<bool> ArchiveAuditLogsAsync(DateTime beforeDate)
        {
            try
            {
                var logsToArchive = await _context.AuditLogs
                    .Where(a => a.Timestamp < beforeDate)
                    .ToListAsync();

                if (logsToArchive.Any())
                {
                    // Create archive file
                    var archiveData = ExportToJson(logsToArchive);
                    var fileName = $"audit_archive_{beforeDate:yyyyMMdd}_{DateTime.UtcNow:yyyyMMddHHmmss}.json";
                    var archivePath = Path.Combine("Archives", "AuditLogs", fileName);

                    Directory.CreateDirectory(Path.GetDirectoryName(archivePath));
                    await File.WriteAllBytesAsync(archivePath, archiveData);

                    _logger.LogInformation($"Archived {logsToArchive.Count} audit logs to {fileName}");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error archiving audit logs");
                return false;
            }
        }

        public async Task<List<AuditLog>> SearchAuditLogsAsync(string searchTerm)
        {
            return await _context.AuditLogs
                .Where(a => a.Action.Contains(searchTerm) || 
                           a.Details.Contains(searchTerm) ||
                           a.EntityName.Contains(searchTerm))
                .OrderByDescending(a => a.Timestamp)
                .Take(100)
                .ToListAsync();
        }

        private byte[] ExportToCsv(List<AuditLog> logs)
        {
            var csv = new StringBuilder();
            csv.AppendLine("Timestamp,Action,Details,UserId,IpAddress,UserAgent,Category,Severity");

            foreach (var log in logs)
            {
                csv.AppendLine($"{log.Timestamp:yyyy-MM-dd HH:mm:ss},{log.Action}," +
                    $"\"{log.Details?.Replace("\"", "\"\"")}\",{log.UserId}," +
                    $"{log.IpAddress},{log.UserAgent},{log.Category},{log.Severity}");
            }

            return Encoding.UTF8.GetBytes(csv.ToString());
        }

        private byte[] ExportToJson(List<AuditLog> logs)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(logs, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });

            return Encoding.UTF8.GetBytes(json);
        }

        private string GetClientIpAddress()
        {
            // In a real application, get from HttpContext
            return "127.0.0.1";
        }

        private string GetUserAgent()
        {
            // In a real application, get from HttpContext
            return "System";
        }
    }
}