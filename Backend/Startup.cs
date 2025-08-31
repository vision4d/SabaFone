// SabaFone Security System Automation System (SSAS)
// Backend/Startup.cs
// إعدادات التطبيق - شركة سبأفون
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using AspNetCoreRateLimit;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using SabaFone.Backend.Hubs;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Middleware;
using SabaFone.Backend.Services;
using SabaFone.Backend.Services.Implementation;
using Serilog;
namespace SabaFone.Backend
{
/// <summary>
/// إعدادات بدء التطبيق
/// </summary>
public class Startup
{
private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;
public Startup(IConfiguration configuration, IWebHostEnvironment environment)
    {
        _configuration = configuration;
        _environment = environment;
    }
    
    /// <summary>
    /// Configure application services
    /// </summary>
    public void ConfigureServices(IServiceCollection services)
    {
        // Add CORS
        services.AddCors(options =>
        {
            options.AddPolicy("AllowSpecificOrigins", builder =>
            {
                builder.WithOrigins(
                        _configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? 
                        new[] { "http://localhost:3000", "https://localhost:3001" })
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials()
                    .SetIsOriginAllowedToAllowWildcardSubdomains()
                    .WithExposedHeaders("Content-Disposition", "X-Total-Count", "X-Page-Number", "X-Page-Size");
            });
        });
        
        // Add Database Context
        services.AddDbContext<SsasDbContext>(options =>
        {
            options.UseSqlServer(
                _configuration.GetConnectionString("DefaultConnection"),
                sqlOptions =>
                {
                    sqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                    sqlOptions.CommandTimeout(60);
                    sqlOptions.MigrationsAssembly(typeof(SsasDbContext).Assembly.FullName);
                });
            
            if (_environment.IsDevelopment())
            {
                options.EnableSensitiveDataLogging();
                options.EnableDetailedErrors();
            }
        });
        
        // Add Identity
        services.AddIdentity<User, Role>(options =>
        {
            // Password settings
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequiredLength = 8;
            options.Password.RequiredUniqueChars = 4;
            
            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;
            
            // User settings
            options.User.RequireUniqueEmail = true;
            options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            
            // SignIn settings
            options.SignIn.RequireConfirmedEmail = true;
            options.SignIn.RequireConfirmedPhoneNumber = false;
        })
        .AddEntityFrameworkStores<SsasDbContext>()
        .AddDefaultTokenProviders();
        
        // Add JWT Authentication
        var jwtSettings = _configuration.GetSection("Jwt");
        var secretKey = Encoding.UTF8.GetBytes(jwtSettings["SecretKey"]);
        
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = !_environment.IsDevelopment();
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                ClockSkew = TimeSpan.Zero
            };
            
            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        context.Response.Headers.Add("Token-Expired", "true");
                    }
                    return Task.CompletedTask;
                },
                OnMessageReceived = context =>
                {
                    var accessToken = context.Request.Query["access_token"];
                    var path = context.HttpContext.Request.Path;
                    
                    if (!string.IsNullOrEmpty(accessToken) &&
                        (path.StartsWithSegments("/hubs")))
                    {
                        context.Token = accessToken;
                    }
                    
                    return Task.CompletedTask;
                }
            };
        });
        
        // Add Authorization
        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            
            // Add custom policies
            options.AddPolicy("AdminOnly", policy =>
                policy.RequireRole("Admin"));
            
            options.AddPolicy("SecurityOfficer", policy =>
                policy.RequireRole("Admin", "SecurityOfficer"));
            
            options.AddPolicy("RequireMFA", policy =>
                policy.RequireClaim("MFA", "true"));
        });
        
        // Add Controllers with Newtonsoft.Json
        services.AddControllers()
            .AddNewtonsoftJson(options =>
            {
                options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
                options.SerializerSettings.Converters.Add(new StringEnumConverter());
                options.SerializerSettings.DateFormatHandling = DateFormatHandling.IsoDateFormat;
                options.SerializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Utc;
                options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            })
            .ConfigureApiBehaviorOptions(options =>
            {
                options.InvalidModelStateResponseFactory = context =>
                {
                    var errors = context.ModelState
                        .Where(e => e.Value.Errors.Count > 0)
                        .SelectMany(e => e.Value.Errors.Select(er => new
                        {
                            Field = e.Key,
                            Message = er.ErrorMessage
                        }))
                        .ToList();
                    
                    return new BadRequestObjectResult(new
                    {
                        Success = false,
                        Message = "Validation failed",
                        MessageAr = "فشل التحقق من البيانات",
                        Errors = errors
                    });
                };
            });
        
        // Add API Versioning
        services.AddApiVersioning(config =>
        {
            config.DefaultApiVersion = new ApiVersion(1, 0);
            config.AssumeDefaultVersionWhenUnspecified = true;
            config.ReportApiVersions = true;
        });
        
        services.AddVersionedApiExplorer(options =>
        {
            options.GroupNameFormat = "'v'VVV";
            options.SubstituteApiVersionInUrl = true;
        });
        
        // Add Swagger
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "SabaFone SSAS API",
                Version = "v1",
                Description = "Security System Automation System API Documentation",
                Contact = new OpenApiContact
                {
                    Name = "SabaFone IT Department",
                    Email = "it@sabafone.com",
                    Url = new Uri("https://www.sabafone.com")
                },
                License = new OpenApiLicense
                {
                    Name = "Proprietary",
                    Url = new Uri("https://www.sabafone.com/license")
                }
            });
            
            // Add JWT Authentication
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT"
            });
            
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
            
            // Include XML comments
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            if (File.Exists(xmlPath))
            {
                c.IncludeXmlComments(xmlPath);
            }
            
            c.EnableAnnotations();
        });
        
        // Add SignalR for real-time communication
        services.AddSignalR(options =>
        {
            options.EnableDetailedErrors = _environment.IsDevelopment();
            options.MaximumReceiveMessageSize = 102400; // 100KB
        })
        .AddNewtonsoftJsonProtocol();
        
        // Add Memory Cache
        services.AddMemoryCache();
        
        // Add Distributed Cache (Redis)
        if (!string.IsNullOrEmpty(_configuration.GetConnectionString("Redis")))
        {
            services.AddStackExchangeRedisCache(options =>
            {
                options.Configuration = _configuration.GetConnectionString("Redis");
                options.InstanceName = "SSAS";
            });
        }
        else
        {
            services.AddDistributedMemoryCache();
        }
        
        // Add Response Compression
        services.AddResponseCompression(options =>
        {
            options.EnableForHttps = true;
            options.Providers.Add<Microsoft.AspNetCore.ResponseCompression.BrotliCompressionProvider>();
            options.Providers.Add<Microsoft.AspNetCore.ResponseCompression.GzipCompressionProvider>();
        });
        
        // Add HttpContextAccessor
        services.AddHttpContextAccessor();
        
        // Add Application Services
        RegisterApplicationServices(services);
        
        // Add Background Services
        services.AddHostedService<BackupSchedulerService>();
        services.AddHostedService<VulnerabilityScannerService>();
        services.AddHostedService<ComplianceMonitorService>();
        services.AddHostedService<SecurityEventProcessorService>();
        
        // Add AutoMapper
        services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
        
        // Add Data Protection
        services.AddDataProtection();
        
        // Configure Rate Limiting
        services.Configure<IpRateLimitOptions>(_configuration.GetSection("IpRateLimiting"));
        services.Configure<IpRateLimitPolicies>(_configuration.GetSection("IpRateLimitPolicies"));
        services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
        services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
        services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
    }
    
    /// <summary>
    /// Configure the HTTP request pipeline
    /// </summary>
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IApiVersionDescriptionProvider provider)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }
        
        // Use Serilog request logging
        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
            options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
                diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);
                diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].ToString());
                diagnosticContext.Set("ClientIP", httpContext.Connection.RemoteIpAddress?.ToString());
            };
        });
        
        // Security Headers
        app.Use(async (context, next) =>
        {
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("X-Frame-Options", "DENY");
            context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
            context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';");
            context.Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
            
            await next();
        });
        
        app.UseHttpsRedirection();
        app.UseResponseCompression();
        
        // Use Rate Limiting
        app.UseIpRateLimiting();
        
        app.UseRouting();
        
        app.UseCors("AllowSpecificOrigins");
        
        app.UseAuthentication();
        app.UseAuthorization();
        
        // Custom Middleware
        app.UseMiddleware<ErrorHandlingMiddleware>();
        app.UseMiddleware<RequestLoggingMiddleware>();
        app.UseMiddleware<SecurityHeadersMiddleware>();
        
        // Health Checks
        app.UseHealthChecks("/health", new HealthCheckOptions
        {
            Predicate = _ => true,
            ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
        });
        
        // Swagger
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            foreach (var description in provider.ApiVersionDescriptions)
            {
                c.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json", 
                    $"SabaFone SSAS API {description.GroupName.ToUpperInvariant()}");
            }
            
            c.RoutePrefix = "api-docs";
            c.DocumentTitle = "SabaFone SSAS API Documentation";
            c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.None);
            c.DefaultModelsExpandDepth(-1);
            c.DisplayRequestDuration();
            c.EnableFilter();
            c.EnableDeepLinking();
            c.EnableValidator();
        });
        
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapHub<NotificationHub>("/hubs/notifications");
            endpoints.MapHub<SecurityHub>("/hubs/security");
            endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions
            {
                Predicate = check => check.Tags.Contains("ready")
            });
            endpoints.MapHealthChecks("/health/live", new HealthCheckOptions
            {
                Predicate = _ => false
            });
            
            // Default route
            endpoints.MapGet("/", async context =>
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonConvert.SerializeObject(new
                {
                    Application = "SabaFone SSAS Backend",
                    Version = "1.0.0",
                    Status = "Running",
                    Timestamp = DateTime.UtcNow,
                    Documentation = "/api-docs",
                    Health = "/health"
                }));
            });
        });
    }
    
    /// <summary>
    /// Register application services
    /// </summary>
    private void RegisterApplicationServices(IServiceCollection services)
    {
        // Core Services
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<ISmsService, SmsService>();
        services.AddScoped<INotificationService, NotificationService>();
        
        // Security Services
        services.AddScoped<ISecurityService, SecurityService>();
        services.AddScoped<IThreatIntelligenceService, ThreatIntelligenceService>();
        services.AddScoped<IEncryptionService, EncryptionService>();
        services.AddScoped<IKeyManagementService, KeyManagementService>();
        
        // Vulnerability Services
        services.AddScoped<IVulnerabilityService, VulnerabilityService>();
        services.AddScoped<IScanningService, ScanningService>();
        services.AddScoped<IPatchManagementService, PatchManagementService>();
        
        // Backup Services
        services.AddScoped<IBackupService, BackupService>();
        services.AddScoped<IStorageService, StorageService>();
        
        // Compliance Services
        services.AddScoped<IComplianceService, ComplianceService>();
        services.AddScoped<IReportingService, ReportingService>();
        
        // Repository Pattern (if using)
        services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
        services.AddScoped<IUnitOfWork, UnitOfWork>();
    }
}}
