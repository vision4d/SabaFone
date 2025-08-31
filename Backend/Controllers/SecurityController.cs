

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class SecurityController : ControllerBase
    {
        private readonly ISecurityService _securityService;
        private readonly IThreatIntelligenceService _threatService;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;
        private readonly ILogger<SecurityController> _logger;

        public SecurityController(
            ISecurityService securityService,
            IThreatIntelligenceService threatService,
            IAuditService auditService,
            INotificationService notificationService,
            ILogger<SecurityController> logger)
        {
            _securityService = securityService;
            _threatService = threatService;
            _auditService = auditService;
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// Gets security dashboard data
        /// </summary>
        [HttpGet("dashboard")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetDashboard()
        {
            try
            {
                var metrics = await _securityService.GetSecurityMetricsAsync();
                var threats = await _threatService.GetActiveThreatFeedsAsync();
                var recentEvents = await _securityService.GetRecentSecurityEventsAsync(10);
                
                return Ok(new
                {
                    metrics,
                    threats,
                    recentEvents,
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting security dashboard");
                return StatusCode(500, new { message = "An error occurred while getting dashboard data" });
            }
        }

        /// <summary>
        /// Gets security events
        /// </summary>
        [HttpGet("events")]
        [Authorize(Roles = "Admin,SecurityOfficer,Auditor")]
        public async Task<IActionResult> GetSecurityEvents(
            [FromQuery] DateTime? startDate,
            [FromQuery] DateTime? endDate,
            [FromQuery] string severity,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 50)
        {
            try
            {
                var events = await _securityService.GetSecurityEventsAsync(
                    startDate ?? DateTime.UtcNow.AddDays(-7),
                    endDate ?? DateTime.UtcNow,
                    severity,
                    page,
                    pageSize);
                
                return Ok(events);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting security events");
                return StatusCode(500, new { message = "An error occurred while getting events" });
            }
        }

        /// <summary>
        /// Logs a security event
        /// </summary>
        [HttpPost("events")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> LogSecurityEvent([FromBody] SecurityEventRequest request)
        {
            try
            {
                var eventData = new
                {
                    EventType = request.EventType,
                    Severity = request.Severity,
                    Description = request.Description,
                    SourceIP = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = Request.Headers["User-Agent"].ToString(),
                    UserId = Guid.Parse(User.FindFirst("UserId")?.Value),
                    Timestamp = DateTime.UtcNow
                };

                await _securityService.LogSecurityEventAsync(eventData);
                
                return Ok(new { message = "Event logged successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging security event");
                return StatusCode(500, new { message = "An error occurred while logging event" });
            }
        }

        /// <summary>
        /// Gets threat intelligence data
        /// </summary>
        [HttpGet("threats")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetThreats([FromQuery] string type = null)
        {
            try
            {
                var threats = await _threatService.GetThreatIndicatorsAsync(type);
                return Ok(threats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting threats");
                return StatusCode(500, new { message = "An error occurred while getting threats" });
            }
        }

        /// <summary>
        /// Detects threats
        /// </summary>
        [HttpPost("threats/detect")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> DetectThreats()
        {
            try
            {
                var threats = await _threatService.DetectThreatsAsync();
                
                if (threats.Any())
                {
                    await _notificationService.SendSecurityAlertAsync(
                        "High",
                        $"{threats.Count} new threats detected");
                }
                
                return Ok(new
                {
                    threatsDetected = threats.Count,
                    threats
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting threats");
                return StatusCode(500, new { message = "An error occurred while detecting threats" });
            }
        }

        /// <summary>
        /// Analyzes a potential threat
        /// </summary>
        [HttpPost("threats/analyze")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> AnalyzeThreat([FromBody] ThreatAnalysisRequest request)
        {
            try
            {
                var threat = await _threatService.AnalyzeThreatAsync(
                    request.IpAddress,
                    request.UserAgent,
                    request.Behavior);
                
                return Ok(threat);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat");
                return StatusCode(500, new { message = "An error occurred while analyzing threat" });
            }
        }

        /// <summary>
        /// Blocks an IP address
        /// </summary>
        [HttpPost("block-ip")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> BlockIpAddress([FromBody] BlockIpRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                await _threatService.BlockIpAddressAsync(
                    request.IpAddress,
                    request.Reason,
                    request.DurationHours);
                
                await _auditService.LogAsync(
                    "IP_BLOCKED",
                    $"IP {request.IpAddress} blocked for {request.DurationHours} hours. Reason: {request.Reason}",
                    userId);
                
                return Ok(new { message = "IP address blocked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error blocking IP");
                return StatusCode(500, new { message = "An error occurred while blocking IP" });
            }
        }

        /// <summary>
        /// Unblocks an IP address
        /// </summary>
        [HttpPost("unblock-ip")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> UnblockIpAddress([FromBody] UnblockIpRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                await _threatService.UnblockIpAddressAsync(request.IpAddress);
                
                await _auditService.LogAsync(
                    "IP_UNBLOCKED",
                    $"IP {request.IpAddress} unblocked",
                    userId);
                
                return Ok(new { message = "IP address unblocked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unblocking IP");
                return StatusCode(500, new { message = "An error occurred while unblocking IP" });
            }
        }

        /// <summary>
        /// Gets blocked IP addresses
        /// </summary>
        [HttpGet("blocked-ips")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetBlockedIpAddresses()
        {
            try
            {
                var blockedIps = await _threatService.GetBlockedIpAddressesAsync();
                return Ok(blockedIps);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting blocked IPs");
                return StatusCode(500, new { message = "An error occurred while getting blocked IPs" });
            }
        }

        /// <summary>
        /// Initiates incident response
        /// </summary>
        [HttpPost("incidents")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> CreateIncident([FromBody] IncidentRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                var incident = await _securityService.CreateSecurityIncidentAsync(
                    request.Title,
                    request.Description,
                    request.Severity,
                    userId);
                
                await _notificationService.SendIncidentNotificationAsync(
                    incident.IncidentId,
                    request.Severity,
                    request.Description);
                
                return Ok(incident);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating incident");
                return StatusCode(500, new { message = "An error occurred while creating incident" });
            }
        }

        /// <summary>
        /// Gets security incidents
        /// </summary>
        [HttpGet("incidents")]
        [Authorize(Roles = "Admin,SecurityOfficer,Auditor")]
        public async Task<IActionResult> GetIncidents([FromQuery] string status = null)
        {
            try
            {
                var incidents = await _securityService.GetSecurityIncidentsAsync(status);
                return Ok(incidents);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting incidents");
                return StatusCode(500, new { message = "An error occurred while getting incidents" });
            }
        }

        /// <summary>
        /// Updates incident status
        /// </summary>
        [HttpPut("incidents/{incidentId}/status")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> UpdateIncidentStatus(
            Guid incidentId,
            [FromBody] UpdateIncidentStatusRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                await _securityService.UpdateIncidentStatusAsync(
                    incidentId,
                    request.Status,
                    request.Notes);
                
                await _auditService.LogAsync(
                    "INCIDENT_STATUS_UPDATED",
                    $"Incident {incidentId} status updated to {request.Status}",
                    userId);
                
                return Ok(new { message = "Incident status updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating incident status");
                return StatusCode(500, new { message = "An error occurred while updating status" });
            }
        }

        /// <summary>
        /// Gets security policies
        /// </summary>
        [HttpGet("policies")]
        [Authorize]
        public async Task<IActionResult> GetSecurityPolicies()
        {
            try
            {
                var policies = await _securityService.GetSecurityPoliciesAsync();
                return Ok(policies);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting security policies");
                return StatusCode(500, new { message = "An error occurred while getting policies" });
            }
        }

        /// <summary>
        /// Updates security policy
        /// </summary>
        [HttpPut("policies/{policyId}")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> UpdateSecurityPolicy(
            Guid policyId,
            [FromBody] UpdatePolicyRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                await _securityService.UpdateSecurityPolicyAsync(policyId, request.Settings);
                
                await _auditService.LogAsync(
                    "SECURITY_POLICY_UPDATED",
                    $"Security policy {policyId} updated",
                    userId);
                
                return Ok(new { message = "Policy updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating policy");
                return StatusCode(500, new { message = "An error occurred while updating policy" });
            }
        }

        /// <summary>
        /// Performs security assessment
        /// </summary>
        [HttpPost("assessment")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> PerformSecurityAssessment()
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                var assessment = await _securityService.PerformSecurityAssessmentAsync();
                
                await _auditService.LogAsync(
                    "SECURITY_ASSESSMENT_PERFORMED",
                    $"Security assessment completed. Score: {assessment.Score}",
                    userId);
                
                return Ok(assessment);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing assessment");
                return StatusCode(500, new { message = "An error occurred while performing assessment" });
            }
        }

        /// <summary>
        /// Gets threat statistics
        /// </summary>
        [HttpGet("threats/statistics")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetThreatStatistics([FromQuery] DateTime? startDate)
        {
            try
            {
                var stats = await _threatService.GetThreatStatisticsAsync(startDate);
                return Ok(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting threat statistics");
                return StatusCode(500, new { message = "An error occurred while getting statistics" });
            }
        }

        /// <summary>
        /// Generates security report
        /// </summary>
        [HttpGet("report")]
        [Authorize(Roles = "Admin,SecurityOfficer,Auditor")]
        public async Task<IActionResult> GenerateSecurityReport(
            [FromQuery] DateTime startDate,
            [FromQuery] DateTime endDate)
        {
            try
            {
                var report = await _threatService.GenerateThreatReportAsync(startDate, endDate);
                
                return File(report, "application/pdf", $"security-report-{DateTime.UtcNow:yyyyMMdd}.pdf");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating report");
                return StatusCode(500, new { message = "An error occurred while generating report" });
            }
        }

        #region Request Models

        public class SecurityEventRequest
        {
            public string EventType { get; set; }
            public string Severity { get; set; }
            public string Description { get; set; }
        }

        public class ThreatAnalysisRequest
        {
            public string IpAddress { get; set; }
            public string UserAgent { get; set; }
            public string Behavior { get; set; }
        }

        public class BlockIpRequest
        {
            public string IpAddress { get; set; }
            public string Reason { get; set; }
            public int DurationHours { get; set; } = 24;
        }

        public class UnblockIpRequest
        {
            public string IpAddress { get; set; }
        }

        public class IncidentRequest
        {
            public string Title { get; set; }
            public string Description { get; set; }
            public string Severity { get; set; }
        }

        public class UpdateIncidentStatusRequest
        {
            public string Status { get; set; }
            public string Notes { get; set; }
        }

        public class UpdatePolicyRequest
        {
            public Dictionary<string, object> Settings { get; set; }
        }

        #endregion
    }
}