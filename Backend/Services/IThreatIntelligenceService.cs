using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Security.Models;

namespace SabaFone.Backend.Services
{
    public interface IThreatIntelligenceService
    {
        // Threat Detection
        Task<List<ThreatIntelligence>> DetectThreatsAsync();
        Task<ThreatIntelligence> AnalyzeThreatAsync(string ipAddress, string userAgent, string behavior);
        Task<bool> IsKnownThreatAsync(string indicator);
        Task<double> CalculateThreatScoreAsync(Dictionary<string, object> indicators);
        
        // Threat Intelligence
        Task<ThreatIntelligence> AddThreatIndicatorAsync(string type, string value, string severity);
        Task<List<ThreatIntelligence>> GetThreatIndicatorsAsync(string type = null);
        Task<bool> UpdateThreatIntelligenceAsync(Guid threatId, Dictionary<string, object> updates);
        Task<List<ThreatIntelligence>> GetActiveThreatFeedsAsync();
        
        // IP Reputation
        Task<bool> CheckIpReputationAsync(string ipAddress);
        Task<bool> BlockIpAddressAsync(string ipAddress, string reason, int durationHours = 24);
        Task<bool> UnblockIpAddressAsync(string ipAddress);
        Task<List<string>> GetBlockedIpAddressesAsync();
        
        // Threat Response
        Task<bool> InitiateThreatResponseAsync(Guid threatId, string responseType);
        Task<bool> MitigateThreatAsync(Guid threatId);
        Task<bool> EscalateThreatAsync(Guid threatId, string escalationLevel);
        
        // Reporting
        Task<Dictionary<string, object>> GetThreatStatisticsAsync(DateTime? startDate = null);
        Task<byte[]> GenerateThreatReportAsync(DateTime startDate, DateTime endDate);
        Task<List<object>> GetThreatTrendsAsync(int daysBack = 30);
    }
}