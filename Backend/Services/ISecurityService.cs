using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Services
{
    public interface ISecurityService
    {
        // Security Events
        Task<SecurityEvent> LogSecurityEventAsync(SecurityEvent securityEvent);
        Task<List<SecurityEvent>> GetSecurityEventsAsync(DateTime? startDate = null, DateTime? endDate = null);
        Task<List<SecurityEvent>> GetHighPriorityEventsAsync();
        Task<SecurityEvent> GetSecurityEventByIdAsync(Guid eventId);
        
        // Threat Management
        Task<ThreatIntelligence> AddThreatIntelligenceAsync(ThreatIntelligence threat);
        Task<List<ThreatIntelligence>> GetActiveThreatAsync();
        Task<bool> UpdateThreatStatusAsync(Guid threatId, string status);
        Task<List<ThreatIntelligence>> AnalyzeThreatPatternsAsync();
        
        // Security Policies
        Task<SecurityPolicy> CreateSecurityPolicyAsync(SecurityPolicy policy);
        Task<List<SecurityPolicy>> GetActiveSecurityPoliciesAsync();
        Task<bool> EnforcePolicyAsync(Guid policyId);
        Task<bool> ValidatePolicyComplianceAsync(Guid policyId);
        
        // Incident Response
        Task<Guid> CreateIncidentAsync(string type, string severity, string description);
        Task<bool> EscalateIncidentAsync(Guid incidentId);
        Task<bool> ResolveIncidentAsync(Guid incidentId, string resolution);
        
        // Security Monitoring
        Task<bool> MonitorSystemSecurityAsync();
        Task<Dictionary<string, object>> GetSecurityMetricsAsync();
        Task<List<string>> GetSecurityAlertsAsync();
        Task<bool> TriggerSecurityAlertAsync(string alertType, string message);
    }
}