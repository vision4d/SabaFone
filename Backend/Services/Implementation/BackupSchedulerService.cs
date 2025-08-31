using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NCrontab;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Backups.Models;

namespace SabaFone.Backend.Services.Implementation
{
    public class BackupSchedulerService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<BackupSchedulerService> _logger;
        private readonly Dictionary<Guid, Timer> _scheduledJobs = new();

        public BackupSchedulerService(
            IServiceProvider serviceProvider,
            ILogger<BackupSchedulerService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Backup Scheduler Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await LoadScheduledBackups();
                    await CheckAndExecuteBackups();
                    
                    // Check every minute for scheduled backups
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in backup scheduler service");
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
            }

            _logger.LogInformation("Backup Scheduler Service stopped");
        }

        private async Task LoadScheduledBackups()
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                
                var scheduledJobs = await context.BackupJobs
                    .Where(j => j.IsScheduled && j.IsActive)
                    .ToListAsync();

                foreach (var job in scheduledJobs)
                {
                    if (!_scheduledJobs.ContainsKey(job.JobId))
                    {
                        ScheduleJob(job);
                    }
                }

                // Remove jobs that are no longer scheduled
                var activeJobIds = scheduledJobs.Select(j => j.JobId).ToHashSet();
                var jobsToRemove = _scheduledJobs.Keys.Where(id => !activeJobIds.Contains(id)).ToList();
                
                foreach (var jobId in jobsToRemove)
                {
                    if (_scheduledJobs.TryGetValue(jobId, out var timer))
                    {
                        timer?.Dispose();
                        _scheduledJobs.Remove(jobId);
                    }
                }
            }
        }

        private void ScheduleJob(BackupJob job)
        {
            try
            {
                if (string.IsNullOrEmpty(job.Schedule))
                    return;

                var cron = CrontabSchedule.Parse(job.Schedule);
                var nextRun = cron.GetNextOccurrence(DateTime.UtcNow);
                var delay = nextRun - DateTime.UtcNow;

                if (delay.TotalMilliseconds > 0)
                {
                    var timer = new Timer(
                        async _ => await ExecuteBackupJob(job.JobId),
                        null,
                        delay,
                        Timeout.InfiniteTimeSpan);

                    _scheduledJobs[job.JobId] = timer;
                    
                    _logger.LogInformation($"Scheduled backup job {job.JobName} for {nextRun}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error scheduling backup job {job.JobId}");
            }
        }

        private async Task CheckAndExecuteBackups()
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
                
                var dueJobs = await context.BackupJobs
                    .Where(j => j.IsScheduled && 
                               j.IsActive && 
                               j.NextRunTime != null && 
                               j.NextRunTime <= DateTime.UtcNow)
                    .ToListAsync();

                foreach (var job in dueJobs)
                {
                    await ExecuteBackupJob(job.JobId);
                }
            }
        }

        private async Task ExecuteBackupJob(Guid jobId)
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
                    var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                    
                    var job = await context.BackupJobs.FindAsync(jobId);
                    if (job == null || !job.IsActive)
                        return;

                    _logger.LogInformation($"Executing scheduled backup job: {job.JobName}");

                    // Start backup
                    var backupId = await backupService.StartBackupAsync(job);

                    // Update job statistics
                    job.LastRunTime = DateTime.UtcNow;
                    job.TotalRuns++;
                    
                    // Calculate next run time
                    if (!string.IsNullOrEmpty(job.Schedule))
                    {
                        var cron = CrontabSchedule.Parse(job.Schedule);
                        job.NextRunTime = cron.GetNextOccurrence(DateTime.UtcNow);
                        
                        // Reschedule the job
                        if (_scheduledJobs.TryGetValue(jobId, out var oldTimer))
                        {
                            oldTimer?.Dispose();
                        }
                        ScheduleJob(job);
                    }

                    await context.SaveChangesAsync();

                    // Send notification
                    await notificationService.SendRoleBasedNotificationAsync(
                        "Admin",
                        "Backup Started",
                        $"Scheduled backup '{job.JobName}' has started");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error executing backup job {jobId}");
                
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var job = await context.BackupJobs.FindAsync(jobId);
                    
                    if (job != null)
                    {
                        job.FailedRuns++;
                        await context.SaveChangesAsync();
                    }
                }
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Backup Scheduler Service is stopping");

            // Dispose all timers
            foreach (var timer in _scheduledJobs.Values)
            {
                timer?.Dispose();
            }
            _scheduledJobs.Clear();

            await base.StopAsync(cancellationToken);
        }
    }
}