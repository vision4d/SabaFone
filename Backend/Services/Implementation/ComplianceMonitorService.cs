using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Data;

namespace SabaFone.Backend.Services.Implementation
{
    public class ComplianceMonitorService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<ComplianceMonitorService> _logger;
        private readonly IConfiguration _configuration;
        private readonly int _monitoringIntervalHours;

        public ComplianceMonitorService(
            IServiceProvider serviceProvider,
            ILogger<ComplianceMonitorService> logger,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _configuration = configuration;
            
            _monitoringIntervalHours = _configuration.GetValue<int>("Compliance:MonitoringIntervalHours", 24);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Compliance Monitor Service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CheckComplianceStatus();
                    await CheckUpcomingAudits();
                    await CheckControlEffectiveness();
                    await GenerateComplianceAlerts();
                    
                    await Task.Delay(TimeSpan.FromHours(_monitoringIntervalHours), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in compliance monitor service");
                    await Task.Delay(TimeSpan.FromMinutes(30), stoppingToken);
                }
            }

            _logger.LogInformation("Compliance Monitor Service stopped");
        }

        private async Task CheckComplianceStatus()
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var complianceService = scope.ServiceProvider.GetRequiredService<IComplianceService>();
                    var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                    
                    _logger.LogInformation("Checking compliance status");

                    // Get active compliance frameworks
                    var frameworks = await context.ComplianceFrameworks
                        .Where(f => f.IsActive)
                        .ToListAsync();

                    foreach (var framework in frameworks)
                    {
                        // Calculate compliance score
                        var score = await complianceService.CalculateComplianceScoreAsync(framework.FrameworkId);
                        
                        framework.ComplianceLevel = score;
                        
                        // Check if compliance dropped below threshold
                        if (score < 80 && framework.IsMandatory)
                        {
                            await notificationService.SendRoleBasedNotificationAsync(
                                "ComplianceOfficer",
                                "Compliance Alert",
                                $"Compliance score for {framework.FrameworkName} dropped to {score:F1}%");
                            
                            _logger.LogWarning($"Low compliance score for {framework.FrameworkName}: {score:F1}%");
                        }

                        // Check if assessment is due
                        if (framework.NextAssessmentDate != null && 
                            framework.NextAssessmentDate <= DateTime.UtcNow.AddDays(7))
                        {
                            await notificationService.SendRoleBasedNotificationAsync(
                                "ComplianceOfficer",
                                "Assessment Due",
                                $"Compliance assessment for {framework.FrameworkName} is due on {framework.NextAssessmentDate:yyyy-MM-dd}");
                        }
                    }

                    await context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking compliance status");
            }
        }

        private async Task CheckUpcomingAudits()
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                    
                    // Check for upcoming audits
                    var upcomingAudits = await context.ComplianceAudits
                        .Where(a => a.ScheduledDate != null &&
                                   a.ScheduledDate >= DateTime.UtcNow &&
                                   a.ScheduledDate <= DateTime.UtcNow.AddDays(30) &&
                                   a.Status == "Scheduled")
                        .ToListAsync();

                    foreach (var audit in upcomingAudits)
                    {
                        var daysUntilAudit = (audit.ScheduledDate.Value - DateTime.UtcNow).Days;
                        
                        if (daysUntilAudit == 30 || daysUntilAudit == 14 || daysUntilAudit == 7 || daysUntilAudit == 1)
                        {
                            await notificationService.SendRoleBasedNotificationAsync(
                                "ComplianceOfficer",
                                "Upcoming Audit",
                                $"Audit '{audit.AuditName}' scheduled in {daysUntilAudit} day(s)");
                            
                            _logger.LogInformation($"Audit reminder sent for {audit.AuditName}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking upcoming audits");
            }
        }

        private async Task CheckControlEffectiveness()
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var complianceService = scope.ServiceProvider.GetRequiredService<IComplianceService>();
                    
                    _logger.LogInformation("Checking control effectiveness");

                    // Get controls that need effectiveness review
                    var controlsToReview = await context.ComplianceControls
                        .Where(c => c.LastEffectivenessReview == null ||
                                   c.LastEffectivenessReview < DateTime.UtcNow.AddDays(-90))
                        .Take(10) // Process in batches
                        .ToListAsync();

                    foreach (var control in controlsToReview)
                    {
                        var isEffective = await complianceService.ValidateControlEffectivenessAsync(control.ControlId);
                        
                        control.EffectivenessRating = isEffective ? 
                            Math.Min(control.EffectivenessRating + 1, 10) : 
                            Math.Max(control.EffectivenessRating - 1, 0);
                        
                        control.LastEffectivenessReview = DateTime.UtcNow;
                        
                        if (control.EffectivenessRating < 5)
                        {
                            _logger.LogWarning($"Control {control.ControlIdentifier} effectiveness is low: {control.EffectivenessRating}/10");
                        }
                    }

                    if (controlsToReview.Any())
                    {
                        await context.SaveChangesAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking control effectiveness");
            }
        }

        private async Task GenerateComplianceAlerts()
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                    var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                    
                    // Check for open gaps
                    var openGaps = await context.ComplianceGaps
                        .Where(g => g.Status != "Closed" && g.Severity == "Critical")
                        .CountAsync();

                    if (openGaps > 0)
                    {
                        await notificationService.SendRoleBasedNotificationAsync(
                            "ComplianceOfficer",
                            "Critical Compliance Gaps",
                            $"There are {openGaps} critical compliance gaps that need immediate attention");
                    }

                    // Check for overdue remediations
                    var overdueRemediations = await context.ComplianceRemediations
                        .Where(r => r.DueDate != null && 
                                   r.DueDate < DateTime.UtcNow &&
                                   r.Status != "Completed")
                        .CountAsync();

                    if (overdueRemediations > 0)
                    {
                        await notificationService.SendRoleBasedNotificationAsync(
                            "ComplianceOfficer",
                            "Overdue Remediations",
                            $"{overdueRemediations} compliance remediations are overdue");
                    }

                    // Check compliance trends
                    var recentAssessments = await context.ComplianceAssessments
                        .Where(a => a.AssessmentDate >= DateTime.UtcNow.AddDays(-30))
                        .OrderByDescending(a => a.AssessmentDate)
                        .Take(5)
                        .Select(a => a.ComplianceScore)
                        .ToListAsync();

                    if (recentAssessments.Count >= 3)
                    {
                        var trend = CalculateTrend(recentAssessments);
                        
                        if (trend < -5) // Declining by more than 5%
                        {
                            await notificationService.SendRoleBasedNotificationAsync(
                                "ComplianceOfficer",
                                "Declining Compliance Trend",
                                "Compliance scores have been declining over the past assessments");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating compliance alerts");
            }
        }

        private double CalculateTrend(List<double> values)
        {
            if (values.Count < 2)
                return 0;

            // Simple linear trend calculation
            var firstHalf = values.Take(values.Count / 2).Average();
            var secondHalf = values.Skip(values.Count / 2).Average();
            
            return secondHalf - firstHalf;
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Compliance Monitor Service is stopping");
            await base.StopAsync(cancellationToken);
        }
    }
}