using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;

namespace SabaFone.Backend.Middleware
{
    public class RateLimitingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RateLimitingMiddleware> _logger;
        private readonly IMemoryCache _cache;
        private readonly RateLimitOptions _options;
        private readonly IServiceProvider _serviceProvider;
        private readonly ConcurrentDictionary<string, DateTime> _blockedClients;

        public RateLimitingMiddleware(
            RequestDelegate next,
            ILogger<RateLimitingMiddleware> logger,
            IMemoryCache cache,
            IConfiguration configuration,
            IServiceProvider serviceProvider)
        {
            _next = next;
            _logger = logger;
            _cache = cache;
            _serviceProvider = serviceProvider;
            _options = configuration.GetSection("RateLimit").Get<RateLimitOptions>() 
                ?? new RateLimitOptions();
            _blockedClients = new ConcurrentDictionary<string, DateTime>();
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip rate limiting for excluded paths
            if (IsExcludedPath(context.Request.Path))
            {
                await _next(context);
                return;
            }

            var clientId = GetClientIdentifier(context);
            
            // Check if client is blocked
            if (IsClientBlocked(clientId))
            {
                await HandleBlockedClient(context, clientId);
                return;
            }

            // Get rate limit rules for the endpoint
            var rules = GetRateLimitRules(context);
            
            foreach (var rule in rules)
            {
                var key = $"{rule.Name}_{clientId}_{GetRateLimitPeriodKey(rule.Period)}";
                var requestCount = await GetRequestCountAsync(key);

                if (requestCount >= rule.Limit)
                {
                    await HandleRateLimitExceeded(context, clientId, rule);
                    return;
                }

                await IncrementRequestCountAsync(key, rule.Period);
            }

            // Add rate limit headers
            AddRateLimitHeaders(context, rules);

            await _next(context);
        }

        private string GetClientIdentifier(HttpContext context)
        {
            // Try to get authenticated user ID first
            var userId = context.User?.FindFirst("UserId")?.Value;
            if (!string.IsNullOrEmpty(userId))
            {
                return $"user_{userId}";
            }

            // Fall back to IP address
            var ipAddress = context.Connection.RemoteIpAddress;
            if (ipAddress != null)
            {
                // Handle IPv4-mapped IPv6 addresses
                if (ipAddress.IsIPv4MappedToIPv6)
                {
                    ipAddress = ipAddress.MapToIPv4();
                }
                return $"ip_{ipAddress}";
            }

            // Last resort: use connection ID
            return $"conn_{context.Connection.Id}";
        }

        private bool IsExcludedPath(PathString path)
        {
            var excludedPaths = new[]
            {
                "/health",
                "/metrics",
                "/swagger"
            };

            return excludedPaths.Any(p => path.StartsWithSegments(p));
        }

        private List<RateLimitRule> GetRateLimitRules(HttpContext context)
        {
            var rules = new List<RateLimitRule>();
            var path = context.Request.Path.Value.ToLower();
            var method = context.Request.Method;

            // Global rate limit
            rules.Add(new RateLimitRule
            {
                Name = "Global",
                Limit = _options.GlobalLimit,
                Period = TimeSpan.FromMinutes(1)
            });

            // Authentication endpoints - stricter limits
            if (path.Contains("/auth") || path.Contains("/login"))
            {
                rules.Add(new RateLimitRule
                {
                    Name = "Auth",
                    Limit = 5,
                    Period = TimeSpan.FromMinutes(15)
                });
            }

            // API endpoints
            if (path.StartsWith("/api"))
            {
                // Read operations
                if (method == "GET")
                {
                    rules.Add(new RateLimitRule
                    {
                        Name = "ApiRead",
                        Limit = _options.ApiReadLimit,
                        Period = TimeSpan.FromMinutes(1)
                    });
                }
                // Write operations
                else if (method == "POST" || method == "PUT" || method == "DELETE")
                {
                    rules.Add(new RateLimitRule
                    {
                        Name = "ApiWrite",
                        Limit = _options.ApiWriteLimit,
                        Period = TimeSpan.FromMinutes(1)
                    });
                }
            }

            // Security-sensitive endpoints
            if (path.Contains("/security") || path.Contains("/backup") || path.Contains("/compliance"))
            {
                rules.Add(new RateLimitRule
                {
                    Name = "Sensitive",
                    Limit = 10,
                    Period = TimeSpan.FromMinutes(5)
                });
            }

            return rules;
        }

        private async Task<int> GetRequestCountAsync(string key)
        {
            if (_cache.TryGetValue<int>(key, out var count))
            {
                return count;
            }
            return 0;
        }

        private async Task IncrementRequestCountAsync(string key, TimeSpan period)
        {
            var count = await GetRequestCountAsync(key);
            _cache.Set(key, count + 1, period);
        }

        private string GetRateLimitPeriodKey(TimeSpan period)
        {
            var now = DateTime.UtcNow;
            
            if (period.TotalSeconds <= 60)
                return now.ToString("yyyyMMddHHmmss");
            if (period.TotalMinutes <= 60)
                return now.ToString("yyyyMMddHHmm");
            if (period.TotalHours <= 24)
                return now.ToString("yyyyMMddHH");
            
            return now.ToString("yyyyMMdd");
        }

        private bool IsClientBlocked(string clientId)
        {
            if (_blockedClients.TryGetValue(clientId, out var blockedUntil))
            {
                if (blockedUntil > DateTime.UtcNow)
                {
                    return true;
                }
                
                // Remove expired block
                _blockedClients.TryRemove(clientId, out _);
            }
            return false;
        }

        private async Task HandleRateLimitExceeded(HttpContext context, string clientId, RateLimitRule rule)
        {
            _logger.LogWarning(
                "Rate limit exceeded for client {ClientId} on rule {Rule} - Path: {Path}",
                clientId, rule.Name, context.Request.Path);

            // Log security event
            await LogSecurityEventAsync(context, clientId, rule);

            // Block client temporarily if they repeatedly exceed limits
            await CheckAndBlockRepeatOffender(clientId);

            context.Response.StatusCode = 429; // Too Many Requests
            context.Response.Headers["Retry-After"] = rule.Period.TotalSeconds.ToString();
            
            await context.Response.WriteAsync(
                "Rate limit exceeded. Please try again later.");
        }

        private async Task HandleBlockedClient(HttpContext context, string clientId)
        {
            _logger.LogWarning("Blocked client {ClientId} attempted to access {Path}",
                clientId, context.Request.Path);

            context.Response.StatusCode = 429;
            await context.Response.WriteAsync("Access temporarily blocked due to repeated violations.");
        }

        private async Task CheckAndBlockRepeatOffender(string clientId)
        {
            var violationKey = $"violations_{clientId}";
            var violations = await GetRequestCountAsync(violationKey);
            
            if (violations >= _options.MaxViolations)
            {
                // Block client for increasing duration based on violations
                var blockDuration = TimeSpan.FromMinutes(Math.Pow(2, violations - _options.MaxViolations + 1));
                _blockedClients[clientId] = DateTime.UtcNow.Add(blockDuration);
                
                _logger.LogWarning("Client {ClientId} blocked for {Duration} minutes due to repeated violations",
                    clientId, blockDuration.TotalMinutes);

                // Report to threat intelligence
                await ReportToThreatIntelligence(clientId);
            }
            else
            {
                await IncrementRequestCountAsync(violationKey, TimeSpan.FromHours(1));
            }
        }

        private async Task LogSecurityEventAsync(HttpContext context, string clientId, RateLimitRule rule)
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var securityService = scope.ServiceProvider.GetService<ISecurityService>();
                    if (securityService != null)
                    {
                        await securityService.LogSecurityEventAsync(new
                        {
                            EventType = "RATE_LIMIT_EXCEEDED",
                            Severity = rule.Name == "Auth" ? "High" : "Medium",
                            SourceIP = context.Connection.RemoteIpAddress?.ToString(),
                            UserAgent = context.Request.Headers["User-Agent"].ToString(),
                            Path = context.Request.Path.Value,
                            Method = context.Request.Method,
                            ClientId = clientId,
                            Rule = rule.Name,
                            Limit = rule.Limit
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log security event for rate limit violation");
            }
        }

        private async Task ReportToThreatIntelligence(string clientId)
        {
            try
            {
                if (clientId.StartsWith("ip_"))
                {
                    var ipAddress = clientId.Substring(3);
                    
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var threatService = scope.ServiceProvider.GetService<IThreatIntelligenceService>();
                        if (threatService != null)
                        {
                            await threatService.AddThreatIndicatorAsync(
                                "Rate Limit Violator",
                                ipAddress,
                                "Medium");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to report to threat intelligence");
            }
        }

        private void AddRateLimitHeaders(HttpContext context, List<RateLimitRule> rules)
        {
            var mostRestrictiveRule = rules.OrderBy(r => r.Limit).FirstOrDefault();
            if (mostRestrictiveRule != null)
            {
                var key = $"{mostRestrictiveRule.Name}_{GetClientIdentifier(context)}_{GetRateLimitPeriodKey(mostRestrictiveRule.Period)}";
                var requestCount = _cache.Get<int>(key);
                var remaining = Math.Max(0, mostRestrictiveRule.Limit - requestCount);

                context.Response.Headers["X-RateLimit-Limit"] = mostRestrictiveRule.Limit.ToString();
                context.Response.Headers["X-RateLimit-Remaining"] = remaining.ToString();
                context.Response.Headers["X-RateLimit-Reset"] = 
                    new DateTimeOffset(DateTime.UtcNow.Add(mostRestrictiveRule.Period)).ToUnixTimeSeconds().ToString();
            }
        }

        private class RateLimitOptions
        {
            public int GlobalLimit { get; set; } = 100;
            public int ApiReadLimit { get; set; } = 60;
            public int ApiWriteLimit { get; set; } = 30;
            public int MaxViolations { get; set; } = 3;
        }

        private class RateLimitRule
        {
            public string Name { get; set; }
            public int Limit { get; set; }
            public TimeSpan Period { get; set; }
        }
    }
}