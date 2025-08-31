using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IPatchManagementService
    {
        // Patch Management
        Task<object> CreatePatchAsync(Dictionary<string, object> patchInfo);
        Task<object> GetPatchAsync(Guid patchId);
        Task<List<object>> GetAvailablePatchesAsync();
        Task<List<object>> GetPendingPatchesAsync();
        Task<bool> ApprovePatchAsync(Guid patchId);
        
        // Patch Deployment
        Task<Guid> DeployPatchAsync(Guid deploymentId);
        Task<bool> SchedulePatchDeploymentAsync(Guid patchId, DateTime scheduledTime, List<string> targets);
        Task<bool> RollbackPatchAsync(Guid patchId, string reason);
        Task<object> GetDeploymentStatusAsync(Guid deploymentId);
        
        // Testing
        Task<bool> TestPatchAsync(Guid patchId, string testEnvironment);
        Task<object> GetTestResultsAsync(Guid patchId);
        Task<bool> ValidatePatchCompatibilityAsync(Guid patchId, string systemId);
        
        // Monitoring
        Task<Dictionary<string, object>> GetPatchComplianceAsync();
        Task<List<object>> GetSystemsPendingPatchesAsync();
        Task<bool> SendPatchNotificationsAsync(Guid patchId);
        
        // Reporting
        Task<byte[]> GeneratePatchReportAsync(DateTime startDate, DateTime endDate);
        Task<Dictionary<string, object>> GetPatchStatisticsAsync();
        Task<List<object>> GetPatchHistoryAsync(string systemId = null);
    }
}