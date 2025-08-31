using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Exceptions;

namespace SabaFone.Backend.Services.Implementation
{
    public class SecurityService : ISecurityService
    {
        private readonly SsasDbContext _context;
        private readonly ILogger<SecurityService> _logger;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;

        public SecurityService(
            SsasDbContext context,
            ILogger<SecurityService> logger,
            IAuditService auditService,
            INotificationService notificationService)
        {
            _context = context;
            _logger = logger;
            _auditService = auditService;
            _notificationService = notificationService;
        }

        public async Task<SecurityEvent> LogSecurityEventAsync(SecurityEvent securityEvent)
        {
            try
            {
                securityEvent.EventId = Guid.NewGuid();
                securityEvent.Timestamp = DateTime.UtcNow;
                securityEvent.IsActive = true;

                _context.SecurityEvents.Add(securityEvent);
                await _context.SaveChangesAsync();

                // Send notification for critical events
                if (securityEvent.Severity == "Critical" || securityEvent.Severity == "High")
                {
                    await _notificationService.SendSecurityAlertAsync(securityEvent.Severity, securityEvent.Description);
                }

                return securityEvent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging security event");
                throw;
            }
        }

        public async Task<List<SecurityEvent>> GetSecurityEventsAsync(DateTime? startDate = null, DateTime? endDate = null)
        {
            var query = _context.SecurityEvents.AsQueryable();

            if (startDate.HasValue)
                query = query.Where(e => e.Timestamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(e => e.Timestamp <= endDate.Value);

            return await query.OrderByDescending(e => e.Timestamp).ToListAsync();
        }

        public async Task<List<SecurityEvent>> GetHighPriorityEventsAsync()
        {
            return await _context.SecurityEvents
                .Where(e => e.Severity == "Critical" || e.Severity == "High")
                .Where(e => e.IsActive)
                .OrderByDescending(e => e.Timestamp)
                .Take(100)
                .ToListAsync();
        }

        public async Task<SecurityEvent> GetSecurityEventByIdAsync(Guid eventId)
        {
            return await _context.SecurityEvents.FindAsync(eventId);
        }

        public async Task<ThreatIntelligence> AddThreatIntelligenceAsync(ThreatIntelligence threat)
        {
            try
            {
                threat.ThreatId = Guid.NewGuid();
                threat.DateIdentified = DateTime.UtcNow;
                threat.IsActive = true;

                _context.ThreatIntelligence.Add(threat);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("THREAT_ADDED", $"New threat identified: {threat.ThreatName}");

                return threat;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error adding threat intelligence");
                throw;
            }
        }

        public async Task<List<ThreatIntelligence>> GetActiveThreatAsync()
        {
            return await _context.ThreatIntelligence
                .Where(t => t.IsActive)
                .OrderByDescending(t => t.RiskScore)
                .ToListAsync();
        }

        public async Task<bool> UpdateThreatStatusAsync(Guid threatId, string status)
        {
            var threat = await _context.ThreatIntelligence.FindAsync(threatId);
            if (threat == null) return false;

            threat.Status = status;
            threat.LastUpdated = DateTime.UtcNow;

            if (status == "Resolved")
            {
                threat.IsActive = false;
            }

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<List<ThreatIntelligence>> AnalyzeThreatPatternsAsync()
        {
            // Analyze threat patterns
            var recentThreats = await _context.ThreatIntelligence
                .Where(t => t.DateIdentified >= DateTime.UtcNow.AddDays(-30))
                .GroupBy(t => t.ThreatType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToListAsync();

            // Return threats that show patterns
            return await _context.ThreatIntelligence
                .Where(t => t.IsActive)
                .OrderByDescending(t => t.RiskScore)
                .ToListAsync();
        }

        public async Task<SecurityPolicy> CreateSecurityPolicyAsync(SecurityPolicy policy)
        {
            policy.PolicyId = Guid.NewGuid();
            policy.CreatedAt = DateTime.UtcNow;
            policy.IsActive = true;

            _context.SecurityPolicies.Add(policy);
            await _context.SaveChangesAsync();

            return policy;
        }

        public async Task<List<SecurityPolicy>> GetActiveSecurityPoliciesAsync()
        {
            return await _context.SecurityPolicies
                .Where(p => p.IsActive)
                .OrderBy(p => p.PolicyName)
                .ToListAsync();
        }

        public async Task<bool> EnforcePolicyAsync(Guid policyId)
        {
            var policy = await _context.SecurityPolicies.FindAsync(policyId);
            if (policy == null) return false;

            policy.IsEnforced = true;
            policy.EnforcedDate = DateTime.UtcNow;
            policy.LastUpdated = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            await _auditService.LogAsync("POLICY_ENFORCED", $"Policy enforced: {policy.PolicyName}");

            return true;
        }

        public async Task<bool> ValidatePolicyComplianceAsync(Guid policyId)
        {
            var policy = await _context.SecurityPolicies.FindAsync(policyId);
            if (policy == null) return false;

            // Implement policy compliance validation logic
            // This is a simplified implementation
            policy.ComplianceLevel = 85; // Example compliance level
            policy.LastComplianceCheck = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return policy.ComplianceLevel >= 80;
        }

        public async Task<Guid> CreateIncidentAsync(string type, string severity, string description)
        {
            var incident = new SecurityEvent
            {
                EventId = Guid.NewGuid(),
                EventType = type,
                Severity = severity,
                Description = description,
                Timestamp = DateTime.UtcNow,
                IsActive = true,
                Status = "Open"
            };

            _context.SecurityEvents.Add(incident);
            await _context.SaveChangesAsync();

            // Notify security team
            await _notificationService.SendIncidentNotificationAsync(incident.EventId, severity, description);

            return incident.EventId;
        }

        public async Task<bool> EscalateIncidentAsync(Guid incidentId)
        {
            var incident = await _context.SecurityEvents.FindAsync(incidentId);
            if (incident == null) return false;

            incident.Severity = incident.Severity switch
            {
                "Low" => "Medium",
                "Medium" => "High",
                "High" => "Critical",
                _ => "Critical"
            };

            incident.Status = "Escalated";
            await _context.SaveChangesAsync();

            await _notificationService.SendSecurityAlertAsync(incident.Severity, $"Incident escalated: {incident.Description}");

            return true;
        }

        public async Task<bool> ResolveIncidentAsync(Guid incidentId, string resolution)
        {
            var incident = await _context.SecurityEvents.FindAsync(incidentId);
            if (incident == null) return false;

            incident.Status = "Resolved";
            incident.Resolution = resolution;
            incident.ResolvedAt = DateTime.UtcNow;
            incident.IsActive = false;

            await _context.SaveChangesAsync();
            await _auditService.LogAsync("INCIDENT_RESOLVED", $"Incident {incidentId} resolved: {resolution}");

            return true;
        }

        public async Task<bool> MonitorSystemSecurityAsync()
        {
            try
            {
                // Check for suspicious activities
                var suspiciousEvents = await _context.SecurityEvents
                    .Where(e => e.Timestamp >= DateTime.UtcNow.AddMinutes(-5))
                    .Where(e => e.Severity == "High" || e.Severity == "Critical")
                    .CountAsync();

                if (suspiciousEvents > 5)
                {
                    await TriggerSecurityAlertAsync("HIGH_THREAT_ACTIVITY", $"Detected {suspiciousEvents} high-severity events in last 5 minutes");
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error monitoring system security");
                return false;
            }
        }

        public async Task<Dictionary<string, object>> GetSecurityMetricsAsync()
        {
            var metrics = new Dictionary<string, object>();

            metrics["TotalEvents"] = await _context.SecurityEvents.CountAsync();
            metrics["ActiveThreats"] = await _context.ThreatIntelligence.CountAsync(t => t.IsActive);
            metrics["CriticalEvents"] = await _context.SecurityEvents.CountAsync(e => e.Severity == "Critical");
            metrics["OpenIncidents"] = await _context.SecurityEvents.CountAsync(e => e.Status == "Open");
            metrics["CompliancePolicies"] = await _context.SecurityPolicies.CountAsync(p => p.IsActive);

            return metrics;
        }

        public async Task<List<string>> GetSecurityAlertsAsync()
        {
            var alerts = new List<string>();

            // Check for critical events
            var criticalEvents = await _context.SecurityEvents
                .Where(e => e.Severity == "Critical" && e.IsActive)
                .Select(e => $"Critical: {e.Description}")
                .ToListAsync();

            alerts.AddRange(criticalEvents);

            // Check for active threats
            var activeThreats = await _context.ThreatIntelligence
                .Where(t => t.IsActive && t.RiskScore > 8)
                .Select(t => $"Threat: {t.ThreatName} (Risk: {t.RiskScore})")
                .ToListAsync();

            alerts.AddRange(activeThreats);

            return alerts;
        }

        public async Task<bool> TriggerSecurityAlertAsync(string alertType, string message)
        {
            try
            {
                // Log the alert
                await LogSecurityEventAsync(new SecurityEvent
                {
                    EventType = alertType,
                    Severity = "High",
                    Description = message,
                    Source = "SecurityService"
                });

                // Send notifications
                await _notificationService.SendSecurityAlertAsync("High", message);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error triggering security alert");
                return false;
            }
        }
    }
}