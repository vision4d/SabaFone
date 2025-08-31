using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Exceptions;

namespace SabaFone.Backend.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;
        private readonly IServiceProvider _serviceProvider;

        public ErrorHandlingMiddleware(
            RequestDelegate next,
            ILogger<ErrorHandlingMiddleware> logger,
            IServiceProvider serviceProvider)
        {
            _next = next;
            _logger = logger;
            _serviceProvider = serviceProvider;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            _logger.LogError(exception, "An unhandled exception occurred");

            // Log to security events for critical errors
            await LogSecurityEventAsync(context, exception);

            // Send notification for critical errors
            await SendErrorNotificationAsync(exception);

            var response = context.Response;
            response.ContentType = "application/json";

            var errorResponse = new ErrorResponse
            {
                TraceId = context.TraceIdentifier,
                Timestamp = DateTime.UtcNow
            };

            switch (exception)
            {
                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    errorResponse.Message = "Unauthorized access";
                    errorResponse.ErrorCode = "AUTH_001";
                    break;

                case KeyNotFoundException:
                case FileNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    errorResponse.Message = "Resource not found";
                    errorResponse.ErrorCode = "RES_404";
                    break;

                case ArgumentNullException:
                case ArgumentException:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    errorResponse.Message = "Invalid request parameters";
                    errorResponse.ErrorCode = "REQ_400";
                    break;

                case TimeoutException:
                    response.StatusCode = (int)HttpStatusCode.RequestTimeout;
                    errorResponse.Message = "Request timeout";
                    errorResponse.ErrorCode = "TIMEOUT_408";
                    break;

                case InvalidOperationException:
                    response.StatusCode = (int)HttpStatusCode.Conflict;
                    errorResponse.Message = "Operation conflict";
                    errorResponse.ErrorCode = "CONFLICT_409";
                    break;

                case SecurityException:
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    errorResponse.Message = "Security violation";
                    errorResponse.ErrorCode = "SEC_403";
                    await LogSecurityViolationAsync(context, exception);
                    break;

                default:
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    errorResponse.Message = "An error occurred while processing your request";
                    errorResponse.ErrorCode = "INTERNAL_500";
                    break;
            }

            // Include details only in development
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            {
                errorResponse.Details = exception.Message;
                errorResponse.StackTrace = exception.StackTrace;
            }

            var jsonResponse = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await response.WriteAsync(jsonResponse);
        }

        private async Task LogSecurityEventAsync(HttpContext context, Exception exception)
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var securityService = scope.ServiceProvider.GetService<ISecurityService>();
                    if (securityService != null)
                    {
                        var severity = exception switch
                        {
                            SecurityException => "Critical",
                            UnauthorizedAccessException => "High",
                            _ => "Medium"
                        };

                        await securityService.LogSecurityEventAsync(new
                        {
                            EventType = "UNHANDLED_EXCEPTION",
                            Severity = severity,
                            SourceIP = context.Connection.RemoteIpAddress?.ToString(),
                            UserAgent = context.Request.Headers["User-Agent"].ToString(),
                            Path = context.Request.Path,
                            ExceptionType = exception.GetType().Name,
                            Message = exception.Message
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log security event");
            }
        }

        private async Task LogSecurityViolationAsync(HttpContext context, Exception exception)
        {
            try
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var auditService = scope.ServiceProvider.GetService<IAuditService>();
                    var threatService = scope.ServiceProvider.GetService<IThreatIntelligenceService>();

                    if (auditService != null)
                    {
                        await auditService.LogAsync(
                            "SECURITY_VIOLATION",
                            $"Security violation detected: {exception.Message}",
                            GetUserIdFromContext(context));
                    }

                    if (threatService != null && context.Connection.RemoteIpAddress != null)
                    {
                        await threatService.AnalyzeThreatAsync(
                            context.Connection.RemoteIpAddress.ToString(),
                            context.Request.Headers["User-Agent"].ToString(),
                            "SECURITY_VIOLATION");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log security violation");
            }
        }

        private async Task SendErrorNotificationAsync(Exception exception)
        {
            try
            {
                // Only send notifications for critical errors
                if (exception is SecurityException || 
                    exception is SystemException ||
                    exception.Message.Contains("critical", StringComparison.OrdinalIgnoreCase))
                {
                    using (var scope = _serviceProvider.CreateScope())
                    {
                        var notificationService = scope.ServiceProvider.GetService<INotificationService>();
                        if (notificationService != null)
                        {
                            await notificationService.SendSecurityAlertAsync(
                                "High",
                                $"Critical error in application: {exception.GetType().Name} - {exception.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send error notification");
            }
        }

        private Guid? GetUserIdFromContext(HttpContext context)
        {
            var userIdClaim = context.User?.FindFirst("UserId")?.Value;
            if (Guid.TryParse(userIdClaim, out var userId))
            {
                return userId;
            }
            return null;
        }

        private class ErrorResponse
        {
            public string TraceId { get; set; }
            public DateTime Timestamp { get; set; }
            public string Message { get; set; }
            public string ErrorCode { get; set; }
            public string Details { get; set; }
            public string StackTrace { get; set; }
        }
    }
}