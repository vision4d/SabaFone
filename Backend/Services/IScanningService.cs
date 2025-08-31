using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IScanningService
    {
        // Scan Operations
        Task<Guid> StartScanAsync(string scanType, List<string> targets, Dictionary<string, object> options = null);
        Task<bool> StopScanAsync(Guid scanId);
        Task<object> GetScanStatusAsync(Guid scanId);
        Task<object> GetScanResultsAsync(Guid scanId);
        
        // Scan Configuration
        Task<bool> ConfigureScannerAsync(string scannerType, Dictionary<string, object> configuration);
        Task<List<object>> GetAvailableScannersAsync();
        Task<bool> ValidateScannerConfigurationAsync(string scannerType);
        
        // Scheduled Scans
        Task<Guid> ScheduleScanAsync(string scanType, List<string> targets, string schedule);
        Task<bool> UpdateScheduledScanAsync(Guid scheduleId, Dictionary<string, object> updates);
        Task<bool> DeleteScheduledScanAsync(Guid scheduleId);
        Task<List<object>> GetScheduledScansAsync();
        
        // Scan Results
        Task<bool> ProcessScanResultsAsync(Guid scanId);
        Task<List<object>> GetVulnerabilitiesFromScanAsync(Guid scanId);
        Task<bool> ExportScanResultsAsync(Guid scanId, string format);
        
        // Scan History
        Task<List<object>> GetScanHistoryAsync(DateTime? startDate = null);
        Task<bool> DeleteOldScanResultsAsync(int daysToKeep);
        Task<Dictionary<string, object>> GetScanStatisticsAsync();
        
        // Execution
        Task ExecuteScanAsync(Guid scanId);
    }
}