using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Middleware
{
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SecurityHeadersMiddleware> _logger;
        private readonly SecurityHeadersOptions _options;

        public SecurityHeadersMiddleware(
            RequestDelegate next,
            ILogger<SecurityHeadersMiddleware> logger,
            IConfiguration configuration)
        {
            _next = next;
            _logger = logger;
            _options = configuration.GetSection("SecurityHeaders").Get<SecurityHeadersOptions>() 
                ?? new SecurityHeadersOptions();
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Add security headers before processing the request
            AddSecurityHeaders(context);

            // Remove server header
            RemoveServerHeaders(context);

            // Validate request headers
            if (!ValidateRequestHeaders(context))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid request headers");
                return;
            }

            await _next(context);
        }

        private void AddSecurityHeaders(HttpContext context)
        {
            var headers = context.Response.Headers;

            // Content Security Policy
            if (!string.IsNullOrEmpty(_options.ContentSecurityPolicy))
            {
                headers["Content-Security-Policy"] = _options.ContentSecurityPolicy;
            }
            else
            {
                headers["Content-Security-Policy"] = 
                    "default-src 'self'; " +
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; " +
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
                    "font-src 'self' https://fonts.gstatic.com; " +
                    "img-src 'self' data: https:; " +
                    "connect-src 'self' wss: https:; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'self'; " +
                    "form-action 'self'";
            }

            // X-Content-Type-Options
            headers["X-Content-Type-Options"] = "nosniff";

            // X-Frame-Options
            headers["X-Frame-Options"] = _options.XFrameOptions ?? "DENY";

            // X-XSS-Protection
            headers["X-XSS-Protection"] = "1; mode=block";

            // Referrer-Policy
            headers["Referrer-Policy"] = _options.ReferrerPolicy ?? "strict-origin-when-cross-origin";

            // Strict-Transport-Security (HSTS)
            if (context.Request.IsHttps)
            {
                headers["Strict-Transport-Security"] = 
                    _options.StrictTransportSecurity ?? "max-age=31536000; includeSubDomains; preload";
            }

            // Permissions-Policy (formerly Feature-Policy)
            headers["Permissions-Policy"] = _options.PermissionsPolicy ?? 
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

            // X-Permitted-Cross-Domain-Policies
            headers["X-Permitted-Cross-Domain-Policies"] = "none";

            // Cache-Control for sensitive endpoints
            if (IsSensitiveEndpoint(context.Request.Path))
            {
                headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private";
                headers["Pragma"] = "no-cache";
                headers["Expires"] = "0";
            }

            // Add custom security headers for SSAS
            headers["X-SSAS-Version"] = "1.0";
            headers["X-Request-ID"] = context.TraceIdentifier;

            _logger.LogDebug("Security headers added for request {Path}", context.Request.Path);
        }

        private void RemoveServerHeaders(HttpContext context)
        {
            // Remove server identification headers
            context.Response.Headers.Remove("Server");
            context.Response.Headers.Remove("X-Powered-By");
            context.Response.Headers.Remove("X-AspNet-Version");
            context.Response.Headers.Remove("X-AspNetCore-Version");
        }

        private bool ValidateRequestHeaders(HttpContext context)
        {
            var headers = context.Request.Headers;

            // Check for required headers in production
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Production")
            {
                // Validate Origin header for CORS
                if (context.Request.Method != "GET" && context.Request.Method != "HEAD")
                {
                    var origin = headers["Origin"].ToString();
                    var referer = headers["Referer"].ToString();

                    if (string.IsNullOrEmpty(origin) && string.IsNullOrEmpty(referer))
                    {
                        _logger.LogWarning("Missing Origin/Referer header for {Method} request to {Path}",
                            context.Request.Method, context.Request.Path);
                        
                        if (_options.RequireOriginHeader)
                        {
                            return false;
                        }
                    }

                    // Validate against allowed origins
                    if (!string.IsNullOrEmpty(origin) && _options.AllowedOrigins?.Any() == true)
                    {
                        if (!_options.AllowedOrigins.Contains(origin))
                        {
                            _logger.LogWarning("Invalid origin {Origin} for request to {Path}",
                                origin, context.Request.Path);
                            return false;
                        }
                    }
                }

                // Check for suspicious headers
                if (ContainsSuspiciousHeaders(headers))
                {
                    _logger.LogWarning("Suspicious headers detected from {IP}",
                        context.Connection.RemoteIpAddress);
                    return false;
                }
            }

            return true;
        }

        private bool ContainsSuspiciousHeaders(IHeaderDictionary headers)
        {
            // Check for SQL injection in headers
            foreach (var header in headers)
            {
                if (header.Value.ToString().Contains("' OR ", StringComparison.OrdinalIgnoreCase) ||
                    header.Value.ToString().Contains("DROP TABLE", StringComparison.OrdinalIgnoreCase) ||
                    header.Value.ToString().Contains("<script", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Check for excessively long headers
            if (headers.Any(h => h.Value.ToString().Length > 8192))
            {
                return true;
            }

            // Check for null bytes
            if (headers.Any(h => h.Value.ToString().Contains('\0')))
            {
                return true;
            }

            return false;
        }

        private bool IsSensitiveEndpoint(PathString path)
        {
            var sensitivePaths = new[]
            {
                "/api/auth",
                "/api/users",
                "/api/security",
                "/api/compliance",
                "/api/backup",
                "/api/audit"
            };

            return sensitivePaths.Any(p => path.StartsWithSegments(p));
        }

        private class SecurityHeadersOptions
        {
            public string ContentSecurityPolicy { get; set; }
            public string XFrameOptions { get; set; }
            public string ReferrerPolicy { get; set; }
            public string StrictTransportSecurity { get; set; }
            public string PermissionsPolicy { get; set; }
            public bool RequireOriginHeader { get; set; } = true;
            public string[] AllowedOrigins { get; set; }
        }
    }
}