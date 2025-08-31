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
    public class ThreatIntelligenceService : IThreatIntelligenceService
    {
        private readonly SsasDbContext _context;
        private readonly ILogger<ThreatIntelligenceService> _logger;
        private readonly ISecurityService _securityService;
        private readonly INotificationService _notificationService;
        private readonly HashSet<string> _blockedIps = new();

        public ThreatIntelligenceService(
            SsasDbContext context,
            ILogger<ThreatIntelligenceService> logger,
            ISecurityService securityService,
            INotificationService notificationService)
        {
            _context = context;
            _logger = logger;
            _securityService = securityService;
            _notificationService = notificationService;
        }

        public async Task<List<ThreatIntelligence>> DetectThreatsAsync()
        {
            try
            {
                // Analyze recent security events for threats
                var recentEvents = await _context.SecurityEvents
                    .Where(e => e.Timestamp >= DateTime.UtcNow.AddHours(-1))
                    .ToListAsync();

                var threats = new List<ThreatIntelligence>();

                // Detect brute force attempts
                var bruteForceAttempts = recentEvents
                    .Where(e => e.EventType == "LOGIN_FAILED")
                    .GroupBy(e => e.SourceIP)
                    .Where(g => g.Count() > 5)
                    .ToList();

                foreach (var attempt in bruteForceAttempts)
                {
                    var threat = new ThreatIntelligence
                    {
                        ThreatId = Guid.NewGuid(),
                        ThreatType = "Brute Force",
                        ThreatName = $"Brute Force from {attempt.Key}",
                        Description = $"Multiple failed login attempts from IP {attempt.Key}",
                        Severity = "High",
                        RiskScore = 8,
                        SourceIP = attempt.Key,
                        DateIdentified = DateTime.UtcNow,
                        IsActive = true,
                        Status = "Active"
                    };

                    threats.Add(threat);
                    _context.ThreatIntelligence.Add(threat);
                }

                // Detect suspicious patterns
                var suspiciousPatterns = recentEvents
                    .Where(e => e.Severity == "Critical" || e.Severity == "High")
                    .GroupBy(e => new { e.EventType, e.SourceIP })
                    .Where(g => g.Count() > 3)
                    .ToList();

                foreach (var pattern in suspiciousPatterns)
                {
                    var threat = new ThreatIntelligence
                    {
                        ThreatId = Guid.NewGuid(),
                        ThreatType = "Suspicious Activity",
                        ThreatName = $"Suspicious {pattern.Key.EventType}",
                        Description = $"Repeated {pattern.Key.EventType} from {pattern.Key.SourceIP}",
                        Severity = "Medium",
                        RiskScore = 6,
                        SourceIP = pattern.Key.SourceIP,
                        DateIdentified = DateTime.UtcNow,
                        IsActive = true,
                        Status = "Active"
                    };

                    threats.Add(threat);
                    _context.ThreatIntelligence.Add(threat);
                }

                if (threats.Any())
                {
                    await _context.SaveChangesAsync();
                    
                    // Notify security team
                    foreach (var threat in threats.Where(t => t.RiskScore >= 7))
                    {
                        await _notificationService.SendSecurityAlertAsync(threat.Severity, 
                            $"Threat detected: {threat.ThreatName}");
                    }
                }

                return threats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error detecting threats");
                return new List<ThreatIntelligence>();
            }
        }

        public async Task<ThreatIntelligence> AnalyzeThreatAsync(string ipAddress, string userAgent, string behavior)
        {
            try
            {
                // Calculate threat score based on various factors
                double riskScore = 0;

                // Check if IP is in blocklist
                if (_blockedIps.Contains(ipAddress))
                {
                    riskScore += 5;
                }

                // Check for suspicious user agent
                if (string.IsNullOrEmpty(userAgent) || userAgent.Contains("bot", StringComparison.OrdinalIgnoreCase))
                {
                    riskScore += 2;
                }

                // Analyze behavior patterns
                if (behavior.Contains("scan", StringComparison.OrdinalIgnoreCase) || 
                    behavior.Contains("exploit", StringComparison.OrdinalIgnoreCase))
                {
                    riskScore += 3;
                }

                // Check historical data
                var previousThreats = await _context.ThreatIntelligence
                    .Where(t => t.SourceIP == ipAddress)
                    .CountAsync();
                
                if (previousThreats > 0)
                {
                    riskScore += previousThreats * 0.5;
                }

                riskScore = Math.Min(riskScore, 10); // Cap at 10

                var threat = new ThreatIntelligence
                {
                    ThreatId = Guid.NewGuid(),
                    ThreatType = DetermineThreatType(behavior),
                    ThreatName = $"Threat from {ipAddress}",
                    Description = $"Analyzed threat: {behavior}",
                    Severity = DetermineSeverity(riskScore),
                    RiskScore = riskScore,
                    SourceIP = ipAddress,
                    UserAgent = userAgent,
                    DateIdentified = DateTime.UtcNow,
                    IsActive = riskScore > 3,
                    Status = riskScore > 3 ? "Active" : "Monitoring"
                };

                if (threat.IsActive)
                {
                    _context.ThreatIntelligence.Add(threat);
                    await _context.SaveChangesAsync();
                }

                return threat;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error analyzing threat from {ipAddress}");
                throw;
            }
        }

        public async Task<bool> IsKnownThreatAsync(string indicator)
        {
            // Check various threat indicators
            var isThreat = await _context.ThreatIntelligence
                .AnyAsync(t => t.IsActive && (
                    t.SourceIP == indicator ||
                    t.ThreatIndicator == indicator ||
                    t.Domain == indicator));

            return isThreat || _blockedIps.Contains(indicator);
        }

        public async Task<double> CalculateThreatScoreAsync(Dictionary<string, object> indicators)
        {
            double score = 0;

            // Check each indicator
            foreach (var indicator in indicators)
            {
                switch (indicator.Key.ToLower())
                {
                    case "ip":
                        if (await IsKnownThreatAsync(indicator.Value.ToString()))
                            score += 3;
                        break;
                    
                    case "failed_logins":
                        var failedLogins = Convert.ToInt32(indicator.Value);
                        if (failedLogins > 5) score += 2;
                        if (failedLogins > 10) score += 3;
                        break;
                    
                    case "suspicious_activity":
                        if (Convert.ToBoolean(indicator.Value))
                            score += 2;
                        break;
                    
                    case "malware_detected":
                        if (Convert.ToBoolean(indicator.Value))
                            score += 5;
                        break;
                }
            }

            return Math.Min(score, 10);
        }

        public async Task<ThreatIntelligence> AddThreatIndicatorAsync(string type, string value, string severity)
        {
            var threat = new ThreatIntelligence
            {
                ThreatId = Guid.NewGuid(),
                ThreatType = type,
                ThreatIndicator = value,
                ThreatName = $"{type}: {value}",
                Description = $"Threat indicator added: {type} - {value}",
                Severity = severity,
                RiskScore = severity switch
                {
                    "Critical" => 9,
                    "High" => 7,
                    "Medium" => 5,
                    "Low" => 3,
                    _ => 1
                },
                DateIdentified = DateTime.UtcNow,
                IsActive = true,
                Status = "Active"
            };

            _context.ThreatIntelligence.Add(threat);
            await _context.SaveChangesAsync();

            return threat;
        }

        public async Task<List<ThreatIntelligence>> GetThreatIndicatorsAsync(string type = null)
        {
            var query = _context.ThreatIntelligence.Where(t => t.IsActive);

            if (!string.IsNullOrEmpty(type))
            {
                query = query.Where(t => t.ThreatType == type);
            }

            return await query
                .OrderByDescending(t => t.RiskScore)
                .ThenByDescending(t => t.DateIdentified)
                .ToListAsync();
        }

        public async Task<bool> UpdateThreatIntelligenceAsync(Guid threatId, Dictionary<string, object> updates)
        {
            var threat = await _context.ThreatIntelligence.FindAsync(threatId);
            if (threat == null) return false;

            foreach (var update in updates)
            {
                switch (update.Key.ToLower())
                {
                    case "status":
                        threat.Status = update.Value.ToString();
                        break;
                    case "severity":
                        threat.Severity = update.Value.ToString();
                        break;
                    case "riskscore":
                        threat.RiskScore = Convert.ToDouble(update.Value);
                        break;
                    case "description":
                        threat.Description = update.Value.ToString();
                        break;
                }
            }

            threat.LastUpdated = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<List<ThreatIntelligence>> GetActiveThreatFeedsAsync()
        {
            // In production, this would integrate with external threat feeds
            return await _context.ThreatIntelligence
                .Where(t => t.IsActive && t.DateIdentified >= DateTime.UtcNow.AddDays(-7))
                .OrderByDescending(t => t.RiskScore)
                .ToListAsync();
        }

        public async Task<bool> CheckIpReputationAsync(string ipAddress)
        {
            // Check internal blocklist
            if (_blockedIps.Contains(ipAddress))
                return false;

            // Check database for known threats
            var isThreat = await _context.ThreatIntelligence
                .AnyAsync(t => t.SourceIP == ipAddress && t.IsActive);

            // In production, also check external IP reputation services
            
            return !isThreat;
        }

        public async Task<bool> BlockIpAddressAsync(string ipAddress, string reason, int durationHours = 24)
        {
            try
            {
                _blockedIps.Add(ipAddress);

                // Add to threat intelligence
                var threat = new ThreatIntelligence
                {
                    ThreatId = Guid.NewGuid(),
                    ThreatType = "Blocked IP",
                    ThreatName = $"Blocked: {ipAddress}",
                    Description = reason,
                    SourceIP = ipAddress,
                    Severity = "High",
                    RiskScore = 8,
                    DateIdentified = DateTime.UtcNow,
                    BlockedUntil = DateTime.UtcNow.AddHours(durationHours),
                    IsActive = true,
                    Status = "Blocked"
                };

                _context.ThreatIntelligence.Add(threat);
                await _context.SaveChangesAsync();

                _logger.LogWarning($"IP {ipAddress} blocked for {durationHours} hours. Reason: {reason}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error blocking IP {ipAddress}");
                return false;
            }
        }

        public async Task<bool> UnblockIpAddressAsync(string ipAddress)
        {
            _blockedIps.Remove(ipAddress);

            var threats = await _context.ThreatIntelligence
                .Where(t => t.SourceIP == ipAddress && t.Status == "Blocked")
                .ToListAsync();

            foreach (var threat in threats)
            {
                threat.Status = "Unblocked";
                threat.IsActive = false;
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation($"IP {ipAddress} unblocked");

            return true;
        }

        public async Task<List<string>> GetBlockedIpAddressesAsync()
        {
            var blockedIps = await _context.ThreatIntelligence
                .Where(t => t.Status == "Blocked" && t.IsActive)
                .Select(t => t.SourceIP)
                .Distinct()
                .ToListAsync();

            return blockedIps;
        }

        public async Task<bool> InitiateThreatResponseAsync(Guid threatId, string responseType)
        {
            var threat = await _context.ThreatIntelligence.FindAsync(threatId);
            if (threat == null) return false;

            switch (responseType.ToLower())
            {
                case "block":
                    if (!string.IsNullOrEmpty(threat.SourceIP))
                    {
                        await BlockIpAddressAsync(threat.SourceIP, $"Threat response for {threat.ThreatName}");
                    }
                    break;
                
                case "monitor":
                    threat.Status = "Monitoring";
                    break;
                
                case "escalate":
                    await EscalateThreatAsync(threatId, "High");
                    break;
                
                case "mitigate":
                    await MitigateThreatAsync(threatId);
                    break;
            }

            threat.ResponseInitiated = DateTime.UtcNow;
            threat.ResponseType = responseType;
            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<bool> MitigateThreatAsync(Guid threatId)
        {
            var threat = await _context.ThreatIntelligence.FindAsync(threatId);
            if (threat == null) return false;

            threat.Status = "Mitigated";
            threat.MitigatedAt = DateTime.UtcNow;
            threat.IsActive = false;

            await _context.SaveChangesAsync();

            await _notificationService.SendSecurityAlertAsync("Info", 
                $"Threat mitigated: {threat.ThreatName}");

            return true;
        }

        public async Task<bool> EscalateThreatAsync(Guid threatId, string escalationLevel)
        {
            var threat = await _context.ThreatIntelligence.FindAsync(threatId);
            if (threat == null) return false;

            threat.Severity = escalationLevel;
            threat.RiskScore = Math.Min(threat.RiskScore + 2, 10);
            threat.Status = "Escalated";

            await _context.SaveChangesAsync();

            await _notificationService.SendSecurityAlertAsync(escalationLevel, 
                $"Threat escalated: {threat.ThreatName}");

            return true;
        }

        public async Task<Dictionary<string, object>> GetThreatStatisticsAsync(DateTime? startDate = null)
        {
            var query = _context.ThreatIntelligence.AsQueryable();

            if (startDate.HasValue)
            {
                query = query.Where(t => t.DateIdentified >= startDate.Value);
            }

            var stats = new Dictionary<string, object>
            {
                ["TotalThreats"] = await query.CountAsync(),
                ["ActiveThreats"] = await query.CountAsync(t => t.IsActive),
                ["CriticalThreats"] = await query.CountAsync(t => t.Severity == "Critical"),
                ["HighThreats"] = await query.CountAsync(t => t.Severity == "High"),
                ["BlockedIPs"] = await query.CountAsync(t => t.Status == "Blocked"),
                ["MitigatedThreats"] = await query.CountAsync(t => t.Status == "Mitigated"),
                ["AverageRiskScore"] = await query.AverageAsync(t => (double?)t.RiskScore) ?? 0
            };

            return stats;
        }

        public async Task<byte[]> GenerateThreatReportAsync(DateTime startDate, DateTime endDate)
        {
            var threats = await _context.ThreatIntelligence
                .Where(t => t.DateIdentified >= startDate && t.DateIdentified <= endDate)
                .OrderByDescending(t => t.RiskScore)
                .ToListAsync();

            // Generate report (simplified)
            var report = System.Text.Json.JsonSerializer.Serialize(threats, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });

            return System.Text.Encoding.UTF8.GetBytes(report);
        }

        public async Task<List<object>> GetThreatTrendsAsync(int daysBack = 30)
        {
            var startDate = DateTime.UtcNow.AddDays(-daysBack);
            
            var trends = await _context.ThreatIntelligence
                .Where(t => t.DateIdentified >= startDate)
                .GroupBy(t => t.DateIdentified.Date)
                .Select(g => new
                {
                    Date = g.Key,
                    Count = g.Count(),
                    AverageRiskScore = g.Average(t => t.RiskScore)
                })
                .OrderBy(t => t.Date)
                .ToListAsync();

            return trends.Cast<object>().ToList();
        }

        private string DetermineThreatType(string behavior)
        {
            if (behavior.Contains("brute", StringComparison.OrdinalIgnoreCase))
                return "Brute Force";
            if (behavior.Contains("scan", StringComparison.OrdinalIgnoreCase))
                return "Port Scanning";
            if (behavior.Contains("inject", StringComparison.OrdinalIgnoreCase))
                return "Injection Attack";
            if (behavior.Contains("dos", StringComparison.OrdinalIgnoreCase))
                return "DoS Attack";
            
            return "Unknown";
        }

        private string DetermineSeverity(double riskScore)
        {
            return riskScore switch
            {
                >= 9 => "Critical",
                >= 7 => "High",
                >= 5 => "Medium",
                >= 3 => "Low",
                _ => "Info"
            };
        }
    }
}