using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IReportingService
    {
        // Report Generation
        Task<Guid> CreateReportAsync(string reportName, string reportType, object data, string format, string createdBy);
        Task<object> GetReportAsync(Guid reportId);
        Task<byte[]> GenerateReportAsync(string reportType, Dictionary<string, object> parameters);
        Task<byte[]> ExportReportAsync(Guid reportId, string format);
        
        // Scheduled Reports
        Task<Guid> ScheduleReportAsync(string reportType, string schedule, Dictionary<string, object> parameters);
        Task<bool> UpdateScheduledReportAsync(Guid scheduleId, Dictionary<string, object> updates);
        Task<bool> DeleteScheduledReportAsync(Guid scheduleId);
        Task<List<object>> GetScheduledReportsAsync();
        
        // Report Templates
        Task<object> CreateReportTemplateAsync(string templateName, string templateContent);
        Task<List<object>> GetReportTemplatesAsync();
        Task<bool> UpdateReportTemplateAsync(Guid templateId, string templateContent);
        
        // Dashboard Reports
        Task<Dictionary<string, object>> GetDashboardDataAsync(string dashboardType);
        Task<Dictionary<string, object>> GetExecutiveSummaryAsync();
        Task<Dictionary<string, object>> GetOperationalMetricsAsync();
        
        // Custom Reports
        Task<byte[]> GenerateCustomReportAsync(string query, string format);
        Task<bool> SaveCustomReportAsync(string reportName, string query, Guid userId);
        Task<List<object>> GetCustomReportsAsync(Guid userId);
        
        // Report Distribution
        Task<bool> EmailReportAsync(Guid reportId, List<string> recipients);
        Task<bool> PublishReportAsync(Guid reportId, string location);
        Task<bool> ArchiveReportAsync(Guid reportId);
        
        // Analytics
        Task<Dictionary<string, object>> GetReportAnalyticsAsync();
        Task<List<object>> GetMostViewedReportsAsync(int count = 10);
        Task<Dictionary<string, object>> GetReportUsageStatisticsAsync();
    }
}