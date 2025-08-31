
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;

namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ComplianceController : ControllerBase
    {
        private readonly IComplianceService _complianceService;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;
        private readonly IReportingService _reportingService;
        private readonly ILogger<ComplianceController> _logger;

        public ComplianceController(
            IComplianceService complianceService,
            IAuditService auditService,
            INotificationService notificationService,
            IReportingService reportingService,
            ILogger<ComplianceController> logger)
        {
            _complianceService = complianceService;
            _auditService = auditService;
            _notificationService = notificationService;
            _reportingService = reportingService;
            _logger = logger;
        }

        /// <summary>
        /// Gets compliance dashboard
        /// </summary>
        [HttpGet("dashboard")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetDashboard()
        {
            try
            {
                var dashboardData = await _complianceService.GetComplianceDashboardDataAsync();
                var trends = await _complianceService.GetComplianceTrendsAsync(12);
                var frameworks = await _complianceService.GetComplianceFrameworksAsync();

                return Ok(new
                {
                    metrics = dashboardData,
                    trends,
                    frameworks = frameworks.Take(5),
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting compliance dashboard");
                return StatusCode(500, new { message = "An error occurred while getting dashboard" });
            }
        }

        /// <summary>
        /// Gets compliance frameworks
        /// </summary>
        [HttpGet("frameworks")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetFrameworks()
        {
            try
            {
                var frameworks = await _complianceService.GetComplianceFrameworksAsync();
                return Ok(frameworks);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting compliance frameworks");
                return StatusCode(500, new { message = "An error occurred while getting frameworks" });
            }
        }

        /// <summary>
        /// Creates compliance framework
        /// </summary>
        [HttpPost("frameworks")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> CreateFramework([FromBody] CreateFrameworkRequest request)
        {
            try
            {
                var framework = new Dictionary<string, object>
                {
                    ["Name"] = request.Name,
                    ["Version"] = request.Version,
                    ["Description"] = request.Description,
                    ["Requirements"] = request.Requirements
                };

                var created = await _complianceService.CreateFrameworkAsync(framework);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_FRAMEWORK_CREATED",
                    $"Compliance framework created: {request.Name}",
                    userId);

                return Ok(new { framework = created, message = "Framework created successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating compliance framework");
                return StatusCode(500, new { message = "An error occurred while creating framework" });
            }
        }

        /// <summary>
        /// Updates compliance framework
        /// </summary>
        [HttpPut("frameworks/{frameworkId}")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> UpdateFramework(Guid frameworkId, [FromBody] UpdateFrameworkRequest request)
        {
            try
            {
                var updates = new Dictionary<string, object>();
                
                if (!string.IsNullOrEmpty(request.Name))
                    updates["Name"] = request.Name;
                if (!string.IsNullOrEmpty(request.Version))
                    updates["Version"] = request.Version;
                if (!string.IsNullOrEmpty(request.Description))
                    updates["Description"] = request.Description;

                var result = await _complianceService.UpdateFrameworkAsync(frameworkId, updates);
                
                if (!result)
                {
                    return NotFound(new { message = "Framework not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_FRAMEWORK_UPDATED",
                    $"Compliance framework {frameworkId} updated",
                    userId);

                return Ok(new { message = "Framework updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating framework {frameworkId}");
                return StatusCode(500, new { message = "An error occurred while updating framework" });
            }
        }

        /// <summary>
        /// Starts compliance assessment
        /// </summary>
        [HttpPost("assessment")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> StartAssessment([FromBody] StartAssessmentRequest request)
        {
            try
            {
                var scope = new Dictionary<string, object>
                {
                    ["Systems"] = request.Systems,
                    ["Controls"] = request.Controls,
                    ["AssessmentType"] = request.AssessmentType
                };

                var assessmentId = await _complianceService.StartComplianceAssessmentAsync(
                    request.FrameworkId,
                    scope);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_ASSESSMENT_STARTED",
                    $"Compliance assessment started for framework {request.FrameworkId}",
                    userId);

                return Ok(new { assessmentId, message = "Assessment started successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting compliance assessment");
                return StatusCode(500, new { message = "An error occurred while starting assessment" });
            }
        }

        /// <summary>
        /// Gets assessment results
        /// </summary>
        [HttpGet("assessment/{assessmentId}/results")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetAssessmentResults(Guid assessmentId)
        {
            try
            {
                var results = await _complianceService.GetAssessmentResultsAsync(assessmentId);
                
                if (results == null)
                {
                    return NotFound(new { message = "Assessment not found" });
                }

                return Ok(results);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting assessment results {assessmentId}");
                return StatusCode(500, new { message = "An error occurred while getting results" });
            }
        }

        /// <summary>
        /// Gets compliance controls
        /// </summary>
        [HttpGet("frameworks/{frameworkId}/controls")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetControls(Guid frameworkId)
        {
            try
            {
                var controls = await _complianceService.GetControlsAsync(frameworkId);
                return Ok(controls);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting controls for framework {frameworkId}");
                return StatusCode(500, new { message = "An error occurred while getting controls" });
            }
        }

        /// <summary>
        /// Implements compliance control
        /// </summary>
        [HttpPost("controls/{controlId}/implement")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> ImplementControl(Guid controlId)
        {
            try
            {
                var result = await _complianceService.ImplementControlAsync(controlId);
                
                if (!result)
                {
                    return NotFound(new { message = "Control not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_CONTROL_IMPLEMENTED",
                    $"Compliance control {controlId} implemented",
                    userId);

                return Ok(new { message = "Control implemented successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error implementing control {controlId}");
                return StatusCode(500, new { message = "An error occurred while implementing control" });
            }
        }

        /// <summary>
        /// Validates control effectiveness
        /// </summary>
        [HttpPost("controls/{controlId}/validate")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> ValidateControl(Guid controlId)
        {
            try
            {
                var isEffective = await _complianceService.ValidateControlEffectivenessAsync(controlId);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "CONTROL_EFFECTIVENESS_VALIDATED",
                    $"Control {controlId} effectiveness: {(isEffective ? "Effective" : "Not Effective")}",
                    userId);

                return Ok(new { effective = isEffective });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating control {controlId}");
                return StatusCode(500, new { message = "An error occurred while validating control" });
            }
        }

        /// <summary>
        /// Gets compliance gaps
        /// </summary>
        [HttpGet("frameworks/{frameworkId}/gaps")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetComplianceGaps(Guid frameworkId)
        {
            try
            {
                var gaps = await _complianceService.IdentifyComplianceGapsAsync(frameworkId);
                return Ok(gaps);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error identifying gaps for framework {frameworkId}");
                return StatusCode(500, new { message = "An error occurred while identifying gaps" });
            }
        }

        /// <summary>
        /// Creates remediation plan
        /// </summary>
        [HttpPost("gaps/{gapId}/remediation")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> CreateRemediationPlan(Guid gapId, [FromBody] RemediationPlanRequest request)
        {
            try
            {
                var plan = new Dictionary<string, object>
                {
                    ["Title"] = request.Title,
                    ["Description"] = request.Description,
                    ["Actions"] = request.Actions,
                    ["Timeline"] = request.Timeline,
                    ["Cost"] = request.EstimatedCost,
                    ["Priority"] = request.Priority
                };

                var result = await _complianceService.CreateRemediationPlanAsync(gapId, plan);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "REMEDIATION_PLAN_CREATED",
                    $"Remediation plan created for gap {gapId}",
                    userId);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating remediation plan for gap {gapId}");
                return StatusCode(500, new { message = "An error occurred while creating plan" });
            }
        }

        /// <summary>
        /// Updates remediation progress
        /// </summary>
        [HttpPut("gaps/{gapId}/progress")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> UpdateRemediationProgress(Guid gapId, [FromBody] UpdateProgressRequest request)
        {
            try
            {
                var result = await _complianceService.TrackRemediationProgressAsync(gapId, request.Progress);
                
                if (!result)
                {
                    return NotFound(new { message = "Gap not found" });
                }

                if (request.Progress >= 100)
                {
                    await _notificationService.SendRoleBasedNotificationAsync(
                        "ComplianceOfficer",
                        "Gap Remediated",
                        $"Compliance gap {gapId} has been fully remediated");
                }

                return Ok(new { message = "Progress updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating remediation progress for gap {gapId}");
                return StatusCode(500, new { message = "An error occurred while updating progress" });
            }
        }

        /// <summary>
        /// Schedules compliance audit
        /// </summary>
        [HttpPost("audit/schedule")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> ScheduleAudit([FromBody] ScheduleAuditRequest request)
        {
            try
            {
                var auditId = await _complianceService.ScheduleComplianceAuditAsync(
                    request.FrameworkId,
                    request.AuditDate);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_AUDIT_SCHEDULED",
                    $"Compliance audit scheduled for {request.AuditDate:yyyy-MM-dd}",
                    userId);

                await _notificationService.SendAuditScheduledNotificationAsync(new
                {
                    AuditId = auditId,
                    FrameworkId = request.FrameworkId,
                    ScheduledDate = request.AuditDate
                });

                return Ok(new { auditId, message = "Audit scheduled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scheduling compliance audit");
                return StatusCode(500, new { message = "An error occurred while scheduling audit" });
            }
        }

        /// <summary>
        /// Conducts compliance audit
        /// </summary>
        [HttpPost("audit/{auditId}/conduct")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> ConductAudit(Guid auditId)
        {
            try
            {
                var result = await _complianceService.ConductAuditAsync(auditId);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_AUDIT_CONDUCTED",
                    $"Compliance audit {auditId} conducted",
                    userId);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error conducting audit {auditId}");
                return StatusCode(500, new { message = "An error occurred while conducting audit" });
            }
        }

        /// <summary>
        /// Gets audit findings
        /// </summary>
        [HttpGet("audit/{auditId}/findings")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetAuditFindings(Guid auditId)
        {
            try
            {
                var findings = await _complianceService.GetAuditFindingsAsync(auditId);
                return Ok(findings);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting audit findings for {auditId}");
                return StatusCode(500, new { message = "An error occurred while getting findings" });
            }
        }

        /// <summary>
        /// Attaches evidence to control
        /// </summary>
        [HttpPost("controls/{controlId}/evidence")]
        [Authorize(Roles = "Admin,ComplianceOfficer")]
        public async Task<IActionResult> AttachEvidence(Guid controlId, IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest(new { message = "No file provided" });
                }

                using (var stream = file.OpenReadStream())
                {
                    var data = new byte[file.Length];
                    await stream.ReadAsync(data, 0, data.Length);
                    
                    var result = await _complianceService.AttachEvidenceAsync(controlId, data, file.FileName);
                    
                    if (!result)
                    {
                        return StatusCode(500, new { message = "Failed to attach evidence" });
                    }
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "COMPLIANCE_EVIDENCE_ATTACHED",
                    $"Evidence attached to control {controlId}",
                    userId);

                return Ok(new { message = "Evidence attached successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error attaching evidence to control {controlId}");
                return StatusCode(500, new { message = "An error occurred while attaching evidence" });
            }
        }

        /// <summary>
        /// Gets evidence for control
        /// </summary>
        [HttpGet("controls/{controlId}/evidence")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetEvidence(Guid controlId)
        {
            try
            {
                var evidence = await _complianceService.GetEvidenceAsync(controlId);
                return Ok(evidence);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting evidence for control {controlId}");
                return StatusCode(500, new { message = "An error occurred while getting evidence" });
            }
        }

        /// <summary>
        /// Generates compliance report
        /// </summary>
        [HttpPost("report")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GenerateReport([FromBody] GenerateReportRequest request)
        {
            try
            {
                var report = await _complianceService.GenerateComplianceReportAsync(
                    request.FrameworkId,
                    request.StartDate,
                    request.EndDate,
                    request.ReportType);

                var fileName = $"compliance-report-{request.ReportType}-{DateTime.UtcNow:yyyyMMdd}.pdf";
                
                return File(report, "application/pdf", fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance report");
                return StatusCode(500, new { message = "An error occurred while generating report" });
            }
        }

        /// <summary>
        /// Gets compliance score
        /// </summary>
        [HttpGet("frameworks/{frameworkId}/score")]
        [Authorize(Roles = "Admin,ComplianceOfficer,Auditor")]
        public async Task<IActionResult> GetComplianceScore(Guid frameworkId)
        {
            try
            {
                var score = await _complianceService.CalculateComplianceScoreAsync(frameworkId);
                
                return Ok(new
                {
                    frameworkId,
                    complianceScore = score,
                    rating = GetComplianceRating(score),
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error calculating compliance score for framework {frameworkId}");
                return StatusCode(500, new { message = "An error occurred while calculating score" });
            }
        }

        private string GetComplianceRating(double score)
        {
            if (score >= 95) return "Excellent";
            if (score >= 85) return "Good";
            if (score >= 70) return "Satisfactory";
            if (score >= 50) return "Needs Improvement";
            return "Poor";
        }

        #region Request Models

        public class CreateFrameworkRequest
        {
            public string Name { get; set; }
            public string Version { get; set; }
            public string Description { get; set; }
            public List<string> Requirements { get; set; }
        }

        public class UpdateFrameworkRequest
        {
            public string Name { get; set; }
            public string Version { get; set; }
            public string Description { get; set; }
        }

        public class StartAssessmentRequest
        {
            public Guid FrameworkId { get; set; }
            public List<string> Systems { get; set; }
            public List<string> Controls { get; set; }
            public string AssessmentType { get; set; }
        }

        public class RemediationPlanRequest
        {
            public string Title { get; set; }
            public string Description { get; set; }
            public List<string> Actions { get; set; }
            public string Timeline { get; set; }
            public decimal EstimatedCost { get; set; }
            public string Priority { get; set; }
        }

        public class UpdateProgressRequest
        {
            public int Progress { get; set; }
        }

        public class ScheduleAuditRequest
        {
            public Guid FrameworkId { get; set; }
            public DateTime AuditDate { get; set; }
        }

        public class GenerateReportRequest
        {
            public Guid FrameworkId { get; set; }
            public DateTime StartDate { get; set; }
            public DateTime EndDate { get; set; }
            public string ReportType { get; set; }
        }

        #endregion
    }
}