using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Backups.Models;

namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin,BackupOperator")]
    public class BackupController : ControllerBase
    {
        private readonly IBackupService _backupService;
        private readonly IStorageService _storageService;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;
        private readonly ILogger<BackupController> _logger;

        public BackupController(
            IBackupService backupService,
            IStorageService storageService,
            IAuditService auditService,
            INotificationService notificationService,
            ILogger<BackupController> logger)
        {
            _backupService = backupService;
            _storageService = storageService;
            _auditService = auditService;
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// Gets backup dashboard
        /// </summary>
        [HttpGet("dashboard")]
        public async Task<IActionResult> GetDashboard()
        {
            try
            {
                var statistics = await _backupService.GetBackupStatisticsAsync();
                var jobs = await _backupService.GetBackupJobsAsync();
                var history = await _backupService.GetBackupHistoryAsync();
                var storageStats = await _storageService.GetStorageStatisticsAsync();

                return Ok(new
                {
                    statistics,
                    activeJobs = jobs.Where(j => j.IsActive).Take(5),
                    recentBackups = history.Take(10),
                    storage = new
                    {
                        totalSpace = storageStats.GetValueOrDefault("TotalSpace", 0L),
                        usedSpace = storageStats.GetValueOrDefault("BackupStorageUsed", 0L),
                        availableSpace = storageStats.GetValueOrDefault("AvailableSpace", 0L)
                    },
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting backup dashboard");
                return StatusCode(500, new { message = "An error occurred while getting dashboard" });
            }
        }

        /// <summary>
        /// Gets all backup jobs
        /// </summary>
        [HttpGet("jobs")]
        public async Task<IActionResult> GetBackupJobs([FromQuery] bool activeOnly = true)
        {
            try
            {
                var jobs = await _backupService.GetBackupJobsAsync(activeOnly);
                
                var response = jobs.Select(j => new BackupJobDto
                {
                    JobId = j.JobId,
                    JobName = j.JobName,
                    Description = j.Description,
                    BackupType = j.BackupType,
                    Schedule = j.Schedule,
                    IsScheduled = j.IsScheduled,
                    IsActive = j.IsActive,
                    LastRunTime = j.LastRunTime,
                    NextRunTime = j.NextRunTime,
                    Status = j.Status,
                    TotalRuns = j.TotalRuns,
                    SuccessfulRuns = j.SuccessfulRuns,
                    FailedRuns = j.FailedRuns
                });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting backup jobs");
                return StatusCode(500, new { message = "An error occurred while getting jobs" });
            }
        }

        /// <summary>
        /// Creates new backup job
        /// </summary>
        [HttpPost("jobs")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateBackupJob([FromBody] CreateBackupJobRequest request)
        {
            try
            {
                var job = new BackupJob
                {
                    JobName = request.JobName,
                    Description = request.Description,
                    BackupType = request.BackupType,
                    SourcePath = request.SourcePath,
                    DestinationPath = request.DestinationPath,
                    Schedule = request.Schedule,
                    IsScheduled = !string.IsNullOrEmpty(request.Schedule),
                    RetentionDays = request.RetentionDays,
                    CompressionEnabled = request.CompressionEnabled,
                    EncryptionEnabled = request.EncryptionEnabled,
                    IsActive = true
                };

                var createdJob = await _backupService.CreateBackupJobAsync(job);

                if (job.IsScheduled)
                {
                    await _backupService.ScheduleJobAsync(createdJob.JobId);
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_JOB_CREATED",
                    $"Backup job created: {job.JobName}",
                    userId);

                return Ok(new { jobId = createdJob.JobId, message = "Backup job created successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating backup job");
                return StatusCode(500, new { message = "An error occurred while creating job" });
            }
        }

        /// <summary>
        /// Updates backup job
        /// </summary>
        [HttpPut("jobs/{jobId}")]
        public async Task<IActionResult> UpdateBackupJob(Guid jobId, [FromBody] UpdateBackupJobRequest request)
        {
            try
            {
                var updates = new Dictionary<string, object>();
                
                if (!string.IsNullOrEmpty(request.JobName))
                    updates["JobName"] = request.JobName;
                if (!string.IsNullOrEmpty(request.Description))
                    updates["Description"] = request.Description;
                if (!string.IsNullOrEmpty(request.Schedule))
                    updates["Schedule"] = request.Schedule;
                if (request.RetentionDays.HasValue)
                    updates["RetentionDays"] = request.RetentionDays.Value;

                var result = await _backupService.UpdateBackupJobAsync(jobId, updates);
                
                if (!result)
                {
                    return NotFound(new { message = "Backup job not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_JOB_UPDATED",
                    $"Backup job {jobId} updated",
                    userId);

                return Ok(new { message = "Backup job updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating backup job {jobId}");
                return StatusCode(500, new { message = "An error occurred while updating job" });
            }
        }

        /// <summary>
        /// Deletes backup job
        /// </summary>
        [HttpDelete("jobs/{jobId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteBackupJob(Guid jobId)
        {
            try
            {
                var result = await _backupService.DeleteBackupJobAsync(jobId);
                
                if (!result)
                {
                    return NotFound(new { message = "Backup job not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_JOB_DELETED",
                    $"Backup job {jobId} deleted",
                    userId);

                return Ok(new { message = "Backup job deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting backup job {jobId}");
                return StatusCode(500, new { message = "An error occurred while deleting job" });
            }
        }

        /// <summary>
        /// Starts backup job
        /// </summary>
        [HttpPost("jobs/{jobId}/start")]
        public async Task<IActionResult> StartBackupJob(Guid jobId)
        {
            try
            {
                var job = (await _backupService.GetBackupJobsAsync(false))
                    .FirstOrDefault(j => j.JobId == jobId);
                
                if (job == null)
                {
                    return NotFound(new { message = "Backup job not found" });
                }

                var backupId = await _backupService.StartBackupAsync(job);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_STARTED",
                    $"Backup started for job {job.JobName}",
                    userId);

                return Ok(new { backupId, message = "Backup started successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error starting backup job {jobId}");
                return StatusCode(500, new { message = "An error occurred while starting backup" });
            }
        }

        /// <summary>
        /// Stops running backup
        /// </summary>
        [HttpPost("stop/{backupId}")]
        public async Task<IActionResult> StopBackup(Guid backupId)
        {
            try
            {
                var result = await _backupService.StopBackupAsync(backupId);
                
                if (!result)
                {
                    return NotFound(new { message = "Backup not found or already completed" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_STOPPED",
                    $"Backup {backupId} stopped",
                    userId);

                return Ok(new { message = "Backup stopped successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error stopping backup {backupId}");
                return StatusCode(500, new { message = "An error occurred while stopping backup" });
            }
        }

        /// <summary>
        /// Gets backup status
        /// </summary>
        [HttpGet("status/{backupId}")]
        public async Task<IActionResult> GetBackupStatus(Guid backupId)
        {
            try
            {
                var status = await _backupService.GetBackupStatusAsync(backupId);
                
                if (status == null)
                {
                    return NotFound(new { message = "Backup not found" });
                }

                return Ok(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting backup status {backupId}");
                return StatusCode(500, new { message = "An error occurred while getting status" });
            }
        }

        /// <summary>
        /// Starts restore operation
        /// </summary>
        [HttpPost("restore")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> StartRestore([FromBody] RestoreRequest request)
        {
            try
            {
                // Send approval request for critical restores
                if (request.RestoreType == "Full")
                {
                    await _notificationService.SendRestoreApprovalRequestAsync(new
                    {
                        BackupId = request.BackupId,
                        RestoreType = request.RestoreType,
                        RequestedBy = User.Identity.Name
                    });
                }

                var options = new Dictionary<string, object>
                {
                    ["RestoreType"] = request.RestoreType,
                    ["TargetPath"] = request.TargetPath,
                    ["OverwriteExisting"] = request.OverwriteExisting
                };

                var restoreId = await _backupService.StartRestoreAsync(request.BackupId, options);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "RESTORE_STARTED",
                    $"Restore started from backup {request.BackupId}",
                    userId);

                return Ok(new { restoreId, message = "Restore started successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error starting restore");
                return StatusCode(500, new { message = "An error occurred while starting restore" });
            }
        }

        /// <summary>
        /// Gets restore status
        /// </summary>
        [HttpGet("restore/status/{restoreId}")]
        public async Task<IActionResult> GetRestoreStatus(Guid restoreId)
        {
            try
            {
                var status = await _backupService.GetRestoreStatusAsync(restoreId);
                
                if (status == null)
                {
                    return NotFound(new { message = "Restore operation not found" });
                }

                return Ok(status);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting restore status {restoreId}");
                return StatusCode(500, new { message = "An error occurred while getting status" });
            }
        }

        /// <summary>
        /// Validates backup integrity
        /// </summary>
        [HttpPost("validate/{backupId}")]
        public async Task<IActionResult> ValidateBackup(Guid backupId)
        {
            try
            {
                var isValid = await _backupService.ValidateBackupIntegrityAsync(backupId);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUP_VALIDATED",
                    $"Backup {backupId} validation: {(isValid ? "Success" : "Failed")}",
                    userId);

                return Ok(new { valid = isValid, message = isValid ? "Backup is valid" : "Backup validation failed" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error validating backup {backupId}");
                return StatusCode(500, new { message = "An error occurred while validating backup" });
            }
        }

        /// <summary>
        /// Tests restore operation
        /// </summary>
        [HttpPost("test-restore/{backupId}")]
        public async Task<IActionResult> TestRestore(Guid backupId, [FromQuery] string testEnvironment = "Test")
        {
            try
            {
                var result = await _backupService.TestRestoreAsync(backupId, testEnvironment);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "RESTORE_TEST_PERFORMED",
                    $"Restore test performed for backup {backupId}",
                    userId);

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error testing restore for backup {backupId}");
                return StatusCode(500, new { message = "An error occurred while testing restore" });
            }
        }

        /// <summary>
        /// Rotates old backups
        /// </summary>
        [HttpPost("rotate")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RotateBackups([FromBody] RotateBackupsRequest request)
        {
            try
            {
                var result = await _backupService.CleanupOldBackupsAsync(request.RetentionDays);
                
                if (!result)
                {
                    return StatusCode(500, new { message = "Failed to rotate backups" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "BACKUPS_ROTATED",
                    $"Old backups rotated. Retention: {request.RetentionDays} days",
                    userId);

                return Ok(new { message = "Backups rotated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error rotating backups");
                return StatusCode(500, new { message = "An error occurred while rotating backups" });
            }
        }

        /// <summary>
        /// Gets backup history
        /// </summary>
        [HttpGet("history")]
        public async Task<IActionResult> GetBackupHistory(
            [FromQuery] Guid? jobId = null,
            [FromQuery] int days = 30)
        {
            try
            {
                var history = await _backupService.GetBackupHistoryAsync(jobId);
                
                // Filter by days
                var cutoffDate = DateTime.UtcNow.AddDays(-days);
                var filtered = history.Where(h => 
                {
                    if (h is IDictionary<string, object> dict && dict.TryGetValue("BackupDate", out var date))
                    {
                        if (date is DateTime dt)
                            return dt >= cutoffDate;
                    }
                    return true;
                });

                return Ok(filtered);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting backup history");
                return StatusCode(500, new { message = "An error occurred while getting history" });
            }
        }

        /// <summary>
        /// Generates backup report
        /// </summary>
        [HttpGet("report")]
        public async Task<IActionResult> GenerateReport(
            [FromQuery] DateTime startDate,
            [FromQuery] DateTime endDate)
        {
            try
            {
                var report = await _backupService.GenerateBackupReportAsync(startDate, endDate);
                
                return File(report, "text/plain", $"backup-report-{DateTime.UtcNow:yyyyMMdd}.txt");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating backup report");
                return StatusCode(500, new { message = "An error occurred while generating report" });
            }
        }

        /// <summary>
        /// Gets storage statistics
        /// </summary>
        [HttpGet("storage")]
        public async Task<IActionResult> GetStorageStatistics()
        {
            try
            {
                var stats = await _storageService.GetStorageStatisticsAsync();
                
                return Ok(new
                {
                    totalSpace = FormatBytes((long)stats.GetValueOrDefault("TotalSpace", 0L)),
                    usedSpace = FormatBytes((long)stats.GetValueOrDefault("UsedSpace", 0L)),
                    availableSpace = FormatBytes((long)stats.GetValueOrDefault("AvailableSpace", 0L)),
                    backupSpace = FormatBytes((long)stats.GetValueOrDefault("BackupStorageUsed", 0L)),
                    fileCount = stats.GetValueOrDefault("FileCount", 0L)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting storage statistics");
                return StatusCode(500, new { message = "An error occurred while getting statistics" });
            }
        }

        private string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        #region Request/Response Models

        public class BackupJobDto
        {
            public Guid JobId { get; set; }
            public string JobName { get; set; }
            public string Description { get; set; }
            public string BackupType { get; set; }
            public string Schedule { get; set; }
            public bool IsScheduled { get; set; }
            public bool IsActive { get; set; }
            public DateTime? LastRunTime { get; set; }
            public DateTime? NextRunTime { get; set; }
            public string Status { get; set; }
            public int TotalRuns { get; set; }
            public int SuccessfulRuns { get; set; }
            public int FailedRuns { get; set; }
        }

        public class CreateBackupJobRequest
        {
            public string JobName { get; set; }
            public string Description { get; set; }
            public string BackupType { get; set; }
            public string SourcePath { get; set; }
            public string DestinationPath { get; set; }
            public string Schedule { get; set; }
            public int RetentionDays { get; set; } = 30;
            public bool CompressionEnabled { get; set; } = true;
            public bool EncryptionEnabled { get; set; } = true;
        }

        public class UpdateBackupJobRequest
        {
            public string JobName { get; set; }
            public string Description { get; set; }
            public string Schedule { get; set; }
            public int? RetentionDays { get; set; }
        }

        public class RestoreRequest
        {
            public Guid BackupId { get; set; }
            public string RestoreType { get; set; }
            public string TargetPath { get; set; }
            public bool OverwriteExisting { get; set; }
        }

        public class RotateBackupsRequest
        {
            public int RetentionDays { get; set; } = 30;
        }

        #endregion
    }
}