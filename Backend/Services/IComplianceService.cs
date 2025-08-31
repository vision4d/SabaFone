using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IComplianceService
    {
        // Compliance Assessment
        Task<Guid> StartComplianceAssessmentAsync(Guid frameworkId, Dictionary<string, object> scope);
        Task ExecuteAssessmentAsync(Guid assessmentId);
        Task<object> GetAssessmentResultsAsync(Guid assessmentId);
        Task<double> CalculateComplianceScoreAsync(Guid frameworkId);
        
        // Framework Management
        Task<object> CreateFrameworkAsync(Dictionary<string, object> framework);
        Task<List<object>> GetComplianceFrameworksAsync();
        Task<bool> UpdateFrameworkAsync(Guid frameworkId, Dictionary<string, object> updates);
        
        // Controls
        Task<bool> ImplementControlAsync(Guid controlId);
        Task<bool> ValidateControlEffectivenessAsync(Guid controlId);
        Task<List<object>> GetControlsAsync(Guid frameworkId);
        Task<Dictionary<string, object>> GetControlStatusAsync(Guid controlId);
        
        // Gap Analysis
        Task<List<object>> IdentifyComplianceGapsAsync(Guid frameworkId);
        Task<object> CreateRemediationPlanAsync(Guid gapId, Dictionary<string, object> plan);
        Task<bool> TrackRemediationProgressAsync(Guid gapId, int progress);
        
        // Auditing
        Task<Guid> ScheduleComplianceAuditAsync(Guid frameworkId, DateTime auditDate);
        Task<object> ConductAuditAsync(Guid auditId);
        Task<List<object>> GetAuditFindingsAsync(Guid auditId);
        
        // Reporting
        Task<byte[]> GenerateComplianceReportAsync(Guid frameworkId, DateTime startDate, DateTime endDate, string reportType);
        Task<Dictionary<string, object>> GetComplianceDashboardDataAsync();
        Task<List<object>> GetComplianceTrendsAsync(int monthsBack = 12);
        
        // Evidence Management
        Task<bool> AttachEvidenceAsync(Guid controlId, byte[] evidence, string fileName);
        Task<List<object>> GetEvidenceAsync(Guid controlId);
        Task<bool> ValidateEvidenceAsync(Guid evidenceId);
    }
}