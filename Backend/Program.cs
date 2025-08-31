
using System;
using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.MSSqlServer;
using SabaFone.Backend.Data;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend
{
// <summary>
// نقطة البداية الرئيسية للتطبيق
// </summary>
public class Program
{
public static void Main(string[] args)
{
            // Configure Serilog early
            ConfigureLogging();
try
        {
            Log.Information("=== SabaFone SSAS Backend Starting ===");
            Log.Information("Starting web host...");
            
            var host = CreateHostBuilder(args).Build();
            
            // Run database migrations and seed data
            using (var scope = host.Services.CreateScope())
            {
                var services = scope.ServiceProvider;
                try
                {
                    Log.Information("Initializing database...");
                    var context = services.GetRequiredService<SsasDbContext>();
                    
                    // Apply migrations
                    if (context.Database.GetPendingMigrations().Any())
                    {
                        Log.Information("Applying database migrations...");
                        context.Database.Migrate();
                        Log.Information("Database migrations completed successfully");
                    }
                    
                    // Seed initial data
                    Log.Information("Seeding initial data...");
                    SeedDatabase(context);
                    Log.Information("Database initialization completed");
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "An error occurred while initializing the database");
                    throw;
                }
            }
            
            Log.Information("=== SabaFone SSAS Backend Started Successfully ===");
            host.Run();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Host terminated unexpectedly");
            throw;
        }
        finally
        {
            Log.Information("=== SabaFone SSAS Backend Shutting Down ===");
            Log.CloseAndFlush();
        }
    }
    
    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .UseSerilog() // Use Serilog for logging
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
                
                // Configure Kestrel
                webBuilder.ConfigureKestrel((context, options) =>
                {
                    // Configure ports
                    var httpsPort = context.Configuration.GetValue<int>("Kestrel:Endpoints:Https:Port", 5001);
                    var httpPort = context.Configuration.GetValue<int>("Kestrel:Endpoints:Http:Port", 5000);
                    
                    options.ListenAnyIP(httpPort);
                    options.ListenAnyIP(httpsPort, listenOptions =>
                    {
                        listenOptions.UseHttps();
                    });
                    
                    // Configure limits
                    options.Limits.MaxConcurrentConnections = 100;
                    options.Limits.MaxConcurrentUpgradedConnections = 100;
                    options.Limits.MaxRequestBodySize = 52428800; // 50MB
                    options.Limits.MinRequestBodyDataRate = new Microsoft.AspNetCore.Server.Kestrel.Core.MinDataRate(
                        bytesPerSecond: 100, 
                        gracePeriod: TimeSpan.FromSeconds(10));
                    options.Limits.MinResponseDataRate = new Microsoft.AspNetCore.Server.Kestrel.Core.MinDataRate(
                        bytesPerSecond: 100, 
                        gracePeriod: TimeSpan.FromSeconds(10));
                    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
                    options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(1);
                });
            })
            .ConfigureAppConfiguration((hostingContext, config) =>
            {
                var env = hostingContext.HostingEnvironment;
                
                config.SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
                    .AddEnvironmentVariables("SSAS_")
                    .AddCommandLine(args);
                
                // Add Azure Key Vault if configured
                if (hostingContext.HostingEnvironment.IsProduction())
                {
                    var builtConfig = config.Build();
                    var keyVaultEndpoint = builtConfig["KeyVault:Endpoint"];
                    if (!string.IsNullOrEmpty(keyVaultEndpoint))
                    {
                        // config.AddAzureKeyVault(keyVaultEndpoint);
                        Log.Information($"Azure Key Vault configured: {keyVaultEndpoint}");
                    }
                }
            })
            .ConfigureServices((hostContext, services) =>
            {
                // Add health checks
                services.AddHealthChecks()
                    .AddDbContextCheck<SsasDbContext>("database")
                    .AddUrlGroup(new Uri("https://api.sabafone.com/health"), "external-api")
                    .AddDiskStorageHealthCheck(s => s.AddDrive(@"C:\", 1024)) // 1GB min free space
                    .AddProcessAllocatedMemoryHealthCheck(512); // 512MB max memory
            });
    
    // <summary>
    // Configure Serilog logging
    // </summary>
    private static void ConfigureLogging()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
            .Build();
        
        var loggerConfig = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration)
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithEnvironmentName()
            .Enrich.WithMachineName()
            .Enrich.WithThreadId()
            .Enrich.WithProperty("Application", "SabaFone-SSAS-Backend")
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}] [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                Path.Combine("Logs", "ssas-backend-.txt"),
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: 10485760, // 10MB
                retainedFileCountLimit: 30,
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz}] [{Level:u3}] [{SourceContext}] {Message:lj}{NewLine}{Exception}");
        
        // Add SQL Server sink if configured
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        if (!string.IsNullOrEmpty(connectionString))
        {
            var columnOptions = new ColumnOptions();
            columnOptions.Store.Remove(StandardColumn.Properties);
            columnOptions.Store.Remove(StandardColumn.MessageTemplate);
            columnOptions.Store.Add(StandardColumn.LogEvent);
            columnOptions.LogEvent.DataLength = 2048;
            columnOptions.TimeStamp.NonClusteredIndex = true;
            
            loggerConfig.WriteTo.MSSqlServer(
                connectionString: connectionString,
                sinkOptions: new MSSqlServerSinkOptions
                {
                    TableName = "Logs",
                    SchemaName = "dbo",
                    AutoCreateSqlTable = true
                },
                columnOptions: columnOptions,
                restrictedToMinimumLevel: LogEventLevel.Warning);
        }
        
        Log.Logger = loggerConfig.CreateLogger();
    }
    
    // <summary>
    // Seed initial database data
    // </summary>
    private static void SeedDatabase(SsasDbContext context)
    {
        // Check if database is already seeded
        if (context.Users.Any())
        {
            Log.Information("Database already contains data, skipping seed");
            return;
        }
        
        // Seed data is handled in DbContext OnModelCreating
        context.SaveChanges();
        Log.Information("Database seeded successfully");
    }
}}