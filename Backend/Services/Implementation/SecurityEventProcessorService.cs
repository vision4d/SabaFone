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
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Services.Implementation
{
    public class SecurityEventProcessorService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<SecurityEventProcessorService> _logger;
        private readonly IConfiguration _configuration;
        private readonly Queue<SecurityEvent> _eventQueue = new();
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private readonly int _processingIntervalSeconds;
        private readonly int _batchSize;

        public SecurityEventProcessorService(
            IServiceProvider serviceProvider,
            ILogger<SecurityEventProcessorService> logger,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _configuration = configuration;
            
            _processingIntervalSeconds = _configuration.GetValue<int>("Security:EventProcessingIntervalSeconds", 10);
            _batchSize = _configuration.GetValue<int>("Security:EventBatchSize", 100);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Security Event Processor Service started");

            var tasks = new[]
            {
                ProcessEventsAsync(stoppingToken),
                AnalyzeThreatsAsync(stoppingToken),
                MonitorSecurityMetricsAsync(stoppingToken)
            };

            await Task.WhenAll(tasks);

            _logger.LogInformation("Security Event Processor Service stopped");
        }

        private async Task ProcessEventsAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await ProcessSecurityEvents();
                    await Task.Delay(TimeSpan.FromSeconds(_processingIntervalSeconds), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing security events");
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                }
            }
        }

        private async Task AnalyzeThreatsAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await AnalyzeThreatPatterns();
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error analyzing threats");
                    await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
                }
            }
        }

        private async Task MonitorSecurityMetricsAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await UpdateSecurityMetrics();
                    await Task.Delay(TimeSpan.FromMinutes(15), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error monitoring security metrics");
                    await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                }
            }
        }

        private async Task ProcessSecurityEvents()
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();
                var threatService = scope.ServiceProvider.GetRequiredService<IThreatIntelligenceService>();
                
                // Get unprocessed events
                var unprocessedEvents = await context.SecurityEvents
                    .Where(e => e.ProcessedAt == null)
                    .OrderBy(e => e.Timestamp)
                    .Take(_batchSize)
                    .ToListAsync();

                foreach (var evt in unprocessedEvents)
                {
                    try
                    {
                        // Analyze event for threats
                        if (!string.IsNullOrEmpty(evt.SourceIP))
                        {
                            var threat = await threatService.AnalyzeThreatAsync(
                                evt.SourceIP,
                                evt.UserAgent ?? "",
                                evt.EventType);

                            if (threat.RiskScore > 7)
                            {
                                _logger.LogWarning($"High risk threat detected from {evt.SourceIP}: {threat.ThreatName}");
                                
                                // Block IP if necessary
                                if (threat.RiskScore > 9)
                                {
                                    await threatService.BlockIpAddressAsync(
                                        evt.SourceIP,
                                        $"Auto-blocked due to high risk score: {threat.RiskScore}",
                                        24);
                                }
                            }
                        }

                        // Check for brute force attempts
                        if (evt.EventType == "LOGIN_FAILED")
                        {
                            await CheckBruteForceAttempt(context, evt);
                        }

                        // Mark as processed
                        evt.ProcessedAt = DateTime.UtcNow;
                        evt.ProcessedBy = "SecurityEventProcessor";
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error processing event {evt.EventId}");
                    }
                }

                if (unprocessedEvents.Any())
                {
                    await context.SaveChangesAsync();
                    _logger.LogDebug($"Processed {unprocessedEvents.Count} security events");
                }
            }
        }

        private async Task CheckBruteForceAttempt(SsasDbContext context, SecurityEvent evt)
        {
            if (string.IsNullOrEmpty(evt.SourceIP))
                return;

            // Count failed login attempts from same IP in last hour
            var failedAttempts = await context.SecurityEvents
                .Where(e => e.EventType == "LOGIN_FAILED" &&
                           e.SourceIP == evt.SourceIP &&
                           e.Timestamp >= DateTime.UtcNow.AddHours(-1))
                .CountAsync();

            if (failedAttempts >= 5)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var threatService = scope.ServiceProvider.GetRequiredService<IThreatIntelligenceService>();
                    var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                    
                    // Block IP
                    await threatService.BlockIpAddressAsync(
                        evt.SourceIP,
                        $"Brute force attack detected: {failedAttempts} failed login attempts",
                        6);

                    // Send alert
                    await notificationService.SendSecurityAlertAsync(
                        "High",
                        $"Brute force attack detected from {evt.SourceIP}. IP has been blocked.");
                    
                    _logger.LogWarning($"Brute force attack detected and blocked: {evt.SourceIP}");
                }
            }
        }

        private async Task AnalyzeThreatPatterns()
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                var threatService = scope.ServiceProvider.GetRequiredService<IThreatIntelligenceService>();
                var notificationService = scope.ServiceProvider.GetRequiredService<INotificationService>();
                
                // Detect threat patterns
                var threats = await threatService.DetectThreatsAsync();
                
                if (threats.Any(t => t.Severity == "Critical"))
                {
                    await notificationService.SendSecurityAlertAsync(
                        "Critical",
                        $"Critical threats detected: {string.Join(", ", threats.Where(t => t.Severity == "Critical").Select(t => t.ThreatName))}");
                }

                // Check for suspicious activity patterns
                var suspiciousPatterns = await context.SecurityEvents
                    .Where(e => e.Timestamp >= DateTime.UtcNow.AddMinutes(-30))
                    .GroupBy(e => new { e.EventType, e.SourceIP })
                    .Where(g => g.Count() > 10)
                    .Select(g => new
                    {
                        EventType = g.Key.EventType,
                        SourceIP = g.Key.SourceIP,
                        Count = g.Count()
                    })
                    .ToListAsync();

                foreach (var pattern in suspiciousPatterns)
                {
                    _logger.LogWarning($"Suspicious pattern detected: {pattern.Count} {pattern.EventType} events from {pattern.SourceIP}");
                    
                    // Create threat intelligence entry
                    await threatService.AddThreatIndicatorAsync(
                        "Suspicious Pattern",
                        $"{pattern.EventType} from {pattern.SourceIP}",
                        "Medium");
                }
            }
        }

        private async Task UpdateSecurityMetrics()
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<SsasDbContext>();
                var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();
                
                var metrics = await securityService.GetSecurityMetricsAsync();
                
                _logger.LogInformation($"Security Metrics Update - " +
                    $"Total Events: {metrics["TotalEvents"]}, " +
                    $"Active Threats: {metrics["ActiveThreats"]}, " +
                    $"Critical Events: {metrics["CriticalEvents"]}");

                // Check if metrics exceed thresholds
                if (Convert.ToInt32(metrics["ActiveThreats"]) > 10)
                {
                    using (var notificationScope = _serviceProvider.CreateScope())
                    {
                        var notificationService = notificationScope.ServiceProvider.GetRequiredService<INotificationService>();
                        
                        await notificationService.SendSecurityAlertAsync(
                            "High",
                            $"High number of active threats detected: {metrics["ActiveThreats"]}");
                    }
                }

                // Update system security status
                await UpdateSystemSecurityStatus(context, metrics);
            }
        }

        private async Task UpdateSystemSecurityStatus(SsasDbContext context, Dictionary<string, object> metrics)
        {
            // Calculate overall security score
            var totalEvents = Convert.ToInt32(metrics["TotalEvents"]);
            var criticalEvents = Convert.ToInt32(metrics["CriticalEvents"]);
            var activeThreats = Convert.ToInt32(metrics["ActiveThreats"]);
            
            var securityScore = 100;
            securityScore -= (criticalEvents * 5);
            securityScore -= (activeThreats * 3);
            securityScore = Math.Max(0, Math.Min(100, securityScore));
            
            _logger.LogInformation($"System Security Score: {securityScore}/100");
            
            // Store security score in context or cache
            // This can be used by dashboard and reporting services
        }

        public void QueueEvent(SecurityEvent evt)
        {
            _semaphore.Wait();
            try
            {
                _eventQueue.Enqueue(evt);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Security Event Processor Service is stopping");
            
            // Process remaining events in queue
            while (_eventQueue.Count > 0)
            {
                await ProcessSecurityEvents();
            }
            
            await base.StopAsync(cancellationToken);
        }
    }
}