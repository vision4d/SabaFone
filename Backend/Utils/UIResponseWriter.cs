// Utils/UIResponseWriter.cs
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Diagnostics.HealthChecks;
namespace SabaFone.Backend.Utils
{
    public static class UIResponseWriter
    {
        public static Task WriteHealthCheckResponse(HttpContext context, HealthReport report)
        {
            var result = new
            {
                status = report.Status.ToString(),
                checks = report.Entries.Select(e => new
                {
                    key = e.Key,
                    status = e.Value.Status.ToString(),
                    description = e.Value.Description
                })
            };

            context.Response.ContentType = "application/json";
            return context.Response.WriteAsync(JsonSerializer.Serialize(result));
        }
    }
}