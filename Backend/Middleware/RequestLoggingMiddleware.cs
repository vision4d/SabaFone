using System;
using Microsoft.IO;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IO;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Security.Models;

namespace SabaFone.Backend.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;
        private readonly RecyclableMemoryStreamManager _recyclableMemoryStreamManager;
        private readonly IServiceProvider _serviceProvider;
        
        private readonly HashSet<string> _sensitiveHeaders = new()
        {
            "Authorization",
            "X-API-Key",
            "Cookie",
            "Set-Cookie"
        };

        private readonly HashSet<string> _excludedPaths = new()
        {
            "/health",
            "/metrics",
            "/swagger",
            "/hub"
        };

        public RequestLoggingMiddleware(
            RequestDelegate next,
            ILogger<RequestLoggingMiddleware> logger,
            IServiceProvider serviceProvider)
        {
            _next = next;
            _logger = logger;
            _serviceProvider = serviceProvider;
            _recyclableMemoryStreamManager = new RecyclableMemoryStreamManager();
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip logging for excluded paths
            if (_excludedPaths.Any(path => context.Request.Path.StartsWithSegments(path)))
            {
                await _next(context);
                return;
            }

            var stopwatch = Stopwatch.StartNew();
            var requestInfo = await CaptureRequestAsync(context);

            // Store original response body stream
            var originalBodyStream = context.Response.Body;

            using (var responseBody = _recyclableMemoryStreamManager.GetStream())
            {
                context.Response.Body = responseBody;

                try
                {
                    await _next(context);
                }
                finally
                {
                    stopwatch.Stop();
                    
                    // Capture response
                    var responseInfo = await CaptureResponseAsync(context, responseBody);
                    
                    // Copy the response body back to the original stream
                    await responseBody.CopyToAsync(originalBodyStream);
                    
                    // Log request/response
                    await LogRequestResponseAsync(context, requestInfo, responseInfo, stopwatch.ElapsedMilliseconds);
                    
                    // Log to audit if needed
                    await LogToAuditAsync(context, requestInfo, responseInfo, stopwatch.ElapsedMilliseconds);
                }
            }
        }

        private async Task<RequestInfo> CaptureRequestAsync(HttpContext context)
        {
            var request = context.Request;
            
            var requestInfo = new RequestInfo
            {
                Method = request.Method,
                Path = request.Path,
                QueryString = request.QueryString.ToString(),
                Headers = GetSafeHeaders(request.Headers),
                RemoteIpAddress = context.Connection.RemoteIpAddress?.ToString(),
                UserAgent = request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow,
                TraceId = context.TraceIdentifier
            };

            // Capture request body for POST/PUT/PATCH
            if (request.Method != "GET" && request.Method != "DELETE" && request.ContentLength > 0)
            {
                request.EnableBuffering();
                
                using (var reader = new StreamReader(
                    request.Body,
                    encoding: Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    bufferSize: 1024,
                    leaveOpen: true))
                {
                    requestInfo.Body = await reader.ReadToEndAsync();
                    
                    // Mask sensitive data in body
                    requestInfo.Body = MaskSensitiveData(requestInfo.Body);
                    
                    // Reset the request body stream position
                    request.Body.Position = 0;
                }
            }

            return requestInfo;
        }

        private async Task<ResponseInfo> CaptureResponseAsync(HttpContext context, Stream responseBody)
        {
            responseBody.Seek(0, SeekOrigin.Begin);
            var text = await new StreamReader(responseBody).ReadToEndAsync();
            responseBody.Seek(0, SeekOrigin.Begin);

            return new ResponseInfo
            {
                StatusCode = context.Response.StatusCode,
                Headers = GetSafeHeaders(context.Response.Headers),
                Body = text.Length > 1000 ? text.Substring(0, 1000) + "..." : text,
                ContentType = context.Response.ContentType
            };
        }

        private async Task LogRequestResponseAsync(
            HttpContext context,
            RequestInfo requestInfo,
            ResponseInfo responseInfo,
            long elapsedMs)
        {
            var logLevel = responseInfo.StatusCode >= 500 ? LogLevel.Error :
                          responseInfo.StatusCode >= 400 ? LogLevel.Warning :
                          LogLevel.Information;

            _logger.Log(logLevel,
                "HTTP {Method} {Path} responded {StatusCode} in {ElapsedMs}ms - IP: {RemoteIp} - User: {UserId}",
                requestInfo.Method,
                requestInfo.Path,
                responseInfo.StatusCode,
                elapsedMs,
                requestInfo.RemoteIpAddress,
                GetUserId(context));

            // Log detailed information for errors
            if (responseInfo.StatusCode >= 400)
            {
                _logger.LogDebug(
                    "Request Details - Headers: {Headers}, Body: {Body}",
                    requestInfo.Headers,
                    requestInfo.Body);
                
                _logger.LogDebug(
                    "Response Details - Headers: {Headers}, Body: {Body}",
                    responseInfo.Headers,
                    responseInfo.Body);
            }

            // Log slow requests
            if (elapsedMs > 1000)
            {
                _logger.LogWarning(
                    "Slow request detected: {Method} {Path} took {ElapsedMs}ms",
                    requestInfo.Method,
                    requestInfo.Path,
                    elapsedMs);
            }
        }

        private async Task LogToAuditAsync(
            HttpContext context,
            RequestInfo requestInfo,
            ResponseInfo responseInfo,
            long elapsedMs)
        {
            try
            {
                // Only audit certain operations
                if (ShouldAudit(requestInfo.Method, requestInfo.Path))
                {
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var auditService = scope.ServiceProvider.GetService<IAuditService>();
                        if (auditService != null)
                        {
                            var auditAction = $"{requestInfo.Method}_{requestInfo.Path}";
                            var details = $"Status: {responseInfo.StatusCode}, Duration: {elapsedMs}ms, IP: {requestInfo.RemoteIpAddress}";
                            
                            await auditService.LogAsync(
                                auditAction,
                                details,
                                GetUserIdGuid(context));
                        }
                    }
                }

                // Log security events for suspicious activities
                if (IsSuspiciousActivity(requestInfo, responseInfo))
                {
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var securityService = scope.ServiceProvider.GetService<ISecurityService>();
                        if (securityService != null)
                        {
                            await securityService.LogSecurityEventAsync(new
                            {
                                EventType = "SUSPICIOUS_REQUEST",
                                Severity = "Medium",
                                SourceIP = requestInfo.RemoteIpAddress,
                                UserAgent = requestInfo.UserAgent,
                                Path = requestInfo.Path,
                                Method = requestInfo.Method,
                                StatusCode = responseInfo.StatusCode,
                                Details = $"Suspicious activity detected"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit/security event");
            }
        }

        private bool ShouldAudit(string method, string path)
        {
            // Audit all write operations
            if (method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH")
                return true;

            // Audit sensitive read operations
            if (path.Contains("/users", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/security", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/audit", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/compliance", StringComparison.OrdinalIgnoreCase) ||
                path.Contains("/backup", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private bool IsSuspiciousActivity(RequestInfo request, ResponseInfo response)
        {
            // Multiple 401/403 responses
            if (response.StatusCode == 401 || response.StatusCode == 403)
                return true;

            // SQL injection patterns
            if (request.Body?.Contains("' OR ", StringComparison.OrdinalIgnoreCase) == true ||
                request.QueryString?.Contains("' OR ", StringComparison.OrdinalIgnoreCase) == true)
                return true;

            // Path traversal attempts
            if (request.Path.Contains("../") || request.Path.Contains("..\\"))
                return true;

            // Suspicious user agents
            if (string.IsNullOrEmpty(request.UserAgent) ||
                request.UserAgent.Contains("scanner", StringComparison.OrdinalIgnoreCase) ||
                request.UserAgent.Contains("bot", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private string GetSafeHeaders(IHeaderDictionary headers)
        {
            var safeHeaders = headers
                .Where(h => !_sensitiveHeaders.Contains(h.Key))
                .Select(h => $"{h.Key}={h.Value}");
            
            return string.Join(", ", safeHeaders);
        }

        private string MaskSensitiveData(string data)
        {
            if (string.IsNullOrEmpty(data))
                return data;

            // Mask passwords
            data = System.Text.RegularExpressions.Regex.Replace(
                data,
                @"""password""\s*:\s*""[^""]*""",
                @"""password"":""***MASKED***""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Mask tokens
            data = System.Text.RegularExpressions.Regex.Replace(
                data,
                @"""token""\s*:\s*""[^""]*""",
                @"""token"":""***MASKED***""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            // Mask API keys
            data = System.Text.RegularExpressions.Regex.Replace(
                data,
                @"""apiKey""\s*:\s*""[^""]*""",
                @"""apiKey"":""***MASKED***""",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return data;
        }

        private string GetUserId(HttpContext context)
        {
            return context.User?.FindFirst("UserId")?.Value ?? "Anonymous";
        }

        private Guid? GetUserIdGuid(HttpContext context)
        {
            var userIdStr = GetUserId(context);
            if (Guid.TryParse(userIdStr, out var userId))
                return userId;
            return null;
        }

        private class RequestInfo
        {
            public string Method { get; set; }
            public string Path { get; set; }
            public string QueryString { get; set; }
            public string Headers { get; set; }
            public string Body { get; set; }
            public string RemoteIpAddress { get; set; }
            public string UserAgent { get; set; }
            public DateTime Timestamp { get; set; }
            public string TraceId { get; set; }
        }

        private class ResponseInfo
        {
            public int StatusCode { get; set; }
            public string Headers { get; set; }
            public string Body { get; set; }
            public string ContentType { get; set; }
        }
    }
}