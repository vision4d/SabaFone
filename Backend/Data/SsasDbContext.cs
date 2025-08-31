// 5️⃣ Data/SsasDbContext.cs

/*<artifacts>
<artifact identifier="updated-ssas-db-context" type="application/vnd.ant.code" language="csharp" title="Data/SsasDbContext.cs - Updated">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/SsasDbContext.cs
// سياق قاعدة البيانات الرئيسية المحدث - شركة سبأفون
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Data.Encryption.Models;
using SabaFone.Backend.Data.Vulnerabilities.Models;
using SabaFone.Backend.Data.Backups.Models;
using SabaFone.Backend.Data.Configuration.Models;
namespace SabaFone.Backend.Data
{
/// <summary>
/// سياق قاعدة البيانات الرئيسية لنظام SSAS
/// </summary>
public class SsasDbContext : DbContext
{
private readonly IConfiguration _configuration;
public SsasDbContext(DbContextOptions<SsasDbContext> options, IConfiguration configuration)
            : base(options)
        {
            _configuration = configuration;
        }
        
        #region User Tables
        
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<UserPermission> UserPermissions { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<SessionActivity> SessionActivities { get; set; }
        public DbSet<UserLoginAttempt> UserLoginAttempts { get; set; }
        public DbSet<UserActivity> UserActivities { get; set; }
        public DbSet<UserToken> UserTokens { get; set; }
        public DbSet<UserDevice> UserDevices { get; set; }
        public DbSet<UserNotification> UserNotifications { get; set; }
        
        #endregion
        
        #region Security Tables
        
        public DbSet<SecurityEvent> SecurityEvents { get; set; }
        public DbSet<SecurityEventComment> SecurityEventComments { get; set; }
        public DbSet<SecurityEventAttachment> SecurityEventAttachments { get; set; }
        public DbSet<SecurityEventAction> SecurityEventActions { get; set; }
        public DbSet<Threat> Threats { get; set; }
        public DbSet<ThreatIndicator> ThreatIndicators { get; set; }
        public DbSet<ThreatIntelligence> ThreatIntelligence { get; set; }
        public DbSet<SecurityPolicy> SecurityPolicies { get; set; }
        public DbSet<PolicyViolation> PolicyViolations { get; set; }
        public DbSet<PolicyException> PolicyExceptions { get; set; }
        public DbSet<PolicyReview> PolicyReviews { get; set; }
        public DbSet<ComplianceFramework> ComplianceFrameworks { get; set; }
        public DbSet<ComplianceControl> ComplianceControls { get; set; }
        public DbSet<ComplianceAssessment> ComplianceAssessments { get; set; }
        public DbSet<ComplianceGap> ComplianceGaps { get; set; }
        public DbSet<ComplianceRemediation> ComplianceRemediations { get; set; }
        public DbSet<ComplianceAudit> ComplianceAudits { get; set; }
        public DbSet<ComplianceRequirement> ComplianceRequirements { get; set; }
        
        #endregion
        
        #region Encryption Tables
        
        public DbSet<EncryptionKey> EncryptionKeys { get; set; }
        public DbSet<EncryptionAuditLog> EncryptionAuditLogs { get; set; }
        public DbSet<KeyUsageLog> KeyUsageLogs { get; set; }
        public DbSet<EncryptionPolicy> EncryptionPolicies { get; set; }
        public DbSet<DataEncryptionRecord> DataEncryptionRecords { get; set; }
        
        #endregion
        
        #region Vulnerability Tables
        
        public DbSet<Vulnerability> Vulnerabilities { get; set; }
        public DbSet<VulnerabilityScan> VulnerabilityScans { get; set; }
        public DbSet<ScanResult> ScanResults { get; set; }
        public DbSet<Patch> Patches { get; set; }
        public DbSet<PatchDeployment> PatchDeployments { get; set; }
        public DbSet<RiskAssessment> RiskAssessments { get; set; }
        
        #endregion
        
        #region Backup Tables
        
        public DbSet<BackupJob> BackupJobs { get; set; }
        public DbSet<BackupHistory> BackupHistories { get; set; }
        public DbSet<RestoreTest> RestoreTests { get; set; }
        public DbSet<RestoreOperation> RestoreOperations { get; set; }
        
        #endregion
        
        #region Configuration Tables
        
        public DbSet<SystemSetting> SystemSettings { get; set; }
        public DbSet<SettingHistory> SettingHistories { get; set; }
        public DbSet<NotificationSetting> NotificationSettings { get; set; }
        public DbSet<PasswordPolicy> PasswordPolicies { get; set; }
        public DbSet<ConfigurationTemplate> ConfigurationTemplates { get; set; }
        
        #endregion
        
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                var connectionString = _configuration.GetConnectionString("DefaultConnection");
                optionsBuilder.UseSqlServer(connectionString, options =>
                {
                    options.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                    
                    options.CommandTimeout(60);
                });
                
                // Enable sensitive data logging in development
                if (_configuration["Environment"] == "Development")
                {
                    optionsBuilder.EnableSensitiveDataLogging();
                    optionsBuilder.EnableDetailedErrors();
                }
            }
        }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            
            // Apply configurations
            ApplyUserConfigurations(modelBuilder);
            ApplySecurityConfigurations(modelBuilder);
            ApplyEncryptionConfigurations(modelBuilder);
            ApplyVulnerabilityConfigurations(modelBuilder);
            ApplyBackupConfigurations(modelBuilder);
            ApplyConfigurationConfigurations(modelBuilder);
            
            // Seed initial data
            SeedInitialData(modelBuilder);
        }
        
        private void ApplyUserConfigurations(ModelBuilder modelBuilder)
        {
            // User entity configurations
            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(u => !u.IsDeleted);
            });
            
            // Role entity configurations
            modelBuilder.Entity<Role>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // UserRole composite key
            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.HasOne(ur => ur.User)
                    .WithMany(u => u.UserRoles)
                    .HasForeignKey(ur => ur.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasOne(ur => ur.Role)
                    .WithMany(r => r.UserRoles)
                    .HasForeignKey(ur => ur.RoleId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
            
            // Session configurations
            modelBuilder.Entity<UserSession>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(s => s.IsActive && !s.IsRevoked);
            });
        }
        
        private void ApplySecurityConfigurations(ModelBuilder modelBuilder)
        {
            // Security Event configurations
            modelBuilder.Entity<SecurityEvent>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(e => !e.IsDeleted);
                
                entity.HasMany(e => e.ChildEvents)
                    .WithOne(e => e.ParentEvent)
                    .HasForeignKey(e => e.ParentEventId)
                    .OnDelete(DeleteBehavior.NoAction);
            });
            
            // Threat configurations
            modelBuilder.Entity<Threat>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(t => !t.IsDeleted);
            });
            
            // Policy configurations
            modelBuilder.Entity<SecurityPolicy>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(p => !p.IsDeleted);
            });
            
            // Compliance configurations
            modelBuilder.Entity<ComplianceFramework>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
        }
        
        private void ApplyEncryptionConfigurations(ModelBuilder modelBuilder)
        {
            // Encryption Key configurations
            modelBuilder.Entity<EncryptionKey>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(k => !k.IsDeleted);
                
                entity.HasMany(k => k.ChildKeys)
                    .WithOne(k => k.ParentKey)
                    .HasForeignKey(k => k.ParentKeyId)
                    .OnDelete(DeleteBehavior.NoAction);
            });
            
            // Encryption Audit Log configurations
            modelBuilder.Entity<EncryptionAuditLog>(entity =>
            {
                entity.Property(e => e.Timestamp).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Key Usage Log configurations
            modelBuilder.Entity<KeyUsageLog>(entity =>
            {
                entity.Property(e => e.UsedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Encryption Policy configurations
            modelBuilder.Entity<EncryptionPolicy>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Data Encryption Record configurations
            modelBuilder.Entity<DataEncryptionRecord>(entity =>
            {
                entity.Property(e => e.EncryptedAt).HasDefaultValueSql("GETUTCDATE()");
            });
        }
        
        private void ApplyVulnerabilityConfigurations(ModelBuilder modelBuilder)
        {
            // Vulnerability configurations
            modelBuilder.Entity<Vulnerability>(entity =>
            {
                entity.Property(e => e.DiscoveredAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(v => !v.IsDeleted);
            });
            
            // Vulnerability Scan configurations
            modelBuilder.Entity<VulnerabilityScan>(entity =>
            {
                entity.Property(e => e.ScanDate).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Scan Result configurations
            modelBuilder.Entity<ScanResult>(entity =>
            {
                entity.Property(e => e.FoundAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Patch configurations
            modelBuilder.Entity<Patch>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Patch Deployment configurations
            modelBuilder.Entity<PatchDeployment>(entity =>
            {
                entity.Property(e => e.DeploymentDate).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Risk Assessment configurations
            modelBuilder.Entity<RiskAssessment>(entity =>
            {
                entity.Property(e => e.AssessmentDate).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
        }
        
        private void ApplyBackupConfigurations(ModelBuilder modelBuilder)
        {
            // Backup Job configurations
            modelBuilder.Entity<BackupJob>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasQueryFilter(j => !j.IsDeleted);
            });
            
            // Backup History configurations
            modelBuilder.Entity<BackupHistory>(entity =>
            {
                entity.Property(e => e.BackupDate).HasDefaultValueSql("GETUTCDATE()");
                
                entity.HasMany(h => h.IncrementalBackups)
                    .WithOne(h => h.ParentBackup)
                    .HasForeignKey(h => h.ParentBackupId)
                    .OnDelete(DeleteBehavior.NoAction);
            });
            
            // Restore Test configurations
            modelBuilder.Entity<RestoreTest>(entity =>
            {
                entity.Property(e => e.TestDate).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Restore Operation configurations
            modelBuilder.Entity<RestoreOperation>(entity =>
            {
                entity.Property(e => e.RestoreDate).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
        }
        
        private void ApplyConfigurationConfigurations(ModelBuilder modelBuilder)
        {
            // System Setting configurations
            modelBuilder.Entity<SystemSetting>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Setting History configurations
            modelBuilder.Entity<SettingHistory>(entity =>
            {
                entity.Property(e => e.ChangedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Notification Setting configurations
            modelBuilder.Entity<NotificationSetting>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Password Policy configurations
            modelBuilder.Entity<PasswordPolicy>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });
            
            // Configuration Template configurations
            modelBuilder.Entity<ConfigurationTemplate>(entity =>
            {
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                
                entity.HasMany(t => t.ChildTemplates)
                    .WithOne(t => t.ParentTemplate)
                    .HasForeignKey(t => t.ParentTemplateId)
                    .OnDelete(DeleteBehavior.NoAction);
            });
        }
        
        private void SeedInitialData(ModelBuilder modelBuilder)
        {
            // Seed default roles
            var adminRoleId = Guid.NewGuid();
            var userRoleId = Guid.NewGuid();
            
            modelBuilder.Entity<Role>().HasData(
                new Role
                {
                    RoleId = adminRoleId,
                    RoleName = "Administrator",
                    Description = "System Administrator",
                    ArabicName = "مدير النظام",
                    ArabicDescription = "مدير النظام الكامل",
                    Type = RoleType.System,
                    Priority = 1,
                    IsActive = true,
                    IsSystem = true,
                    IsDeletable = false,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    RoleId = userRoleId,
                    RoleName = "User",
                    Description = "Standard User",
                    ArabicName = "مستخدم",
                    ArabicDescription = "مستخدم عادي",
                    Type = RoleType.System,
                    Priority = 100,
                    IsActive = true,
                    IsSystem = true,
                    IsDeletable = false,
                    CreatedAt = DateTime.UtcNow
                }
            );
            
            // Seed default permissions
            var permissions = new[]
            {
                new Permission
                {
                    PermissionId = Guid.NewGuid(),
                    PermissionName = "users.view",
                    Description = "View users",
                    ArabicName = "عرض المستخدمين",
                    Category = "Users",
                    Resource = "users",
                    Action = "view",
                    IsActive = true,
                    IsSystem = true,
                    Risk = RiskLevel.Low,
                    CreatedAt = DateTime.UtcNow
                },
                new Permission
                {
                    PermissionId = Guid.NewGuid(),
                    PermissionName = "users.create",
                    Description = "Create users",
                    ArabicName = "إنشاء المستخدمين",
                    Category = "Users",
                    Resource = "users",
                    Action = "create",
                    IsActive = true,
                    IsSystem = true,
                    Risk = RiskLevel.High,
                    CreatedAt = DateTime.UtcNow
                },
                new Permission
                {
                    PermissionId = Guid.NewGuid(),
                    PermissionName = "users.update",
                    Description = "Update users",
                    ArabicName = "تحديث المستخدمين",
                    Category = "Users",
                    Resource = "users",
                    Action = "update",
                    IsActive = true,
                    IsSystem = true,
                    Risk = RiskLevel.Medium,
                    CreatedAt = DateTime.UtcNow
                },
                new Permission
                {
                    PermissionId = Guid.NewGuid(),
                    PermissionName = "users.delete",
                    Description = "Delete users",
                    ArabicName = "حذف المستخدمين",
                    Category = "Users",
                    Resource = "users",
                    Action = "delete",
                    IsActive = true,
                    IsSystem = true,
                    Risk = RiskLevel.Critical,
                    CreatedAt = DateTime.UtcNow
                }
            };
            
            modelBuilder.Entity<Permission>().HasData(permissions);
            
            // Seed default compliance frameworks
            modelBuilder.Entity<ComplianceFramework>().HasData(
                new ComplianceFramework
                {
                    FrameworkId = Guid.NewGuid(),
                    FrameworkName = "ISO 27001:2022",
                    FrameworkAcronym = "ISO27001",
                    Description = "Information Security Management System",
                    Version = "2022",
                    IssuingOrganization = "ISO",
                    Industry = "All",
                    Region = "Global",
                    IsActive = true,
                    IsMandatory = true,
                    CreatedAt = DateTime.UtcNow
                },
                new ComplianceFramework
                {
                    FrameworkId = Guid.NewGuid(),
                    FrameworkName = "NIST Cybersecurity Framework",
                    FrameworkAcronym = "NIST CSF",
                    Description = "Framework for Improving Critical Infrastructure Cybersecurity",
                    Version = "2.0",
                    IssuingOrganization = "NIST",
                    Industry = "All",
                    Region = "Global",
                    IsActive = true,
                    IsMandatory = false,
                    CreatedAt = DateTime.UtcNow
                }
            );
            
            // Seed default password policy
            modelBuilder.Entity<PasswordPolicy>().HasData(
                new PasswordPolicy
                {
                    PolicyId = Guid.NewGuid(),
                    PolicyName = "Default Password Policy",
                    Description = "Standard password requirements for all users",
                    IsActive = true,
                    IsDefault = true,
                    MinimumLength = 8,
                    MaximumLength = 128,
                    RequireUppercase = true,
                    MinimumUppercase = 1,
                    RequireLowercase = true,
                    MinimumLowercase = 1,
                    RequireNumbers = true,
                    MinimumNumbers = 1,
                    RequireSpecialCharacters = true,
                    MinimumSpecialCharacters = 1,
                    DisallowUsername = true,
                    DisallowEmail = true,
                    DisallowCommonPasswords = true,
                    EnforceHistory = true,
                    PasswordHistoryCount = 12,
                    PasswordExpires = true,
                    PasswordExpirationDays = 90,
                    EnableAccountLockout = true,
                    MaxFailedAttempts = 5,
                    LockoutDurationMinutes = 30,
                    CreatedAt = DateTime.UtcNow
                }
            );
            
            // Seed default system settings
            modelBuilder.Entity<SystemSetting>().HasData(
                new SystemSetting
                {
                    SettingId = Guid.NewGuid(),
                    SettingKey = "system.name",
                    SettingName = "System Name",
                    SettingValue = "SabaFone Security System",
                    Description = "The name of the system",
                    Category = "General",
                    DataType = SettingType.String,
                    IsRequired = true,
                    IsActive = true,
                    IsReadOnly = true,
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new SystemSetting
                {
                    SettingId = Guid.NewGuid(),
                    SettingKey = "system.version",
                    SettingName = "System Version",
                    SettingValue = "1.0.0",
                    Description = "Current system version",
                    Category = "General",
                    DataType = SettingType.String,
                    IsRequired = true,
                    IsActive = true,
                    IsReadOnly = true,
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new SystemSetting
                {
                    SettingId = Guid.NewGuid(),
                    SettingKey = "security.session.timeout",
                    SettingName = "Session Timeout",
                    SettingValue = "30",
                    Description = "Session timeout in minutes",
                    Category = "Security",
                    DataType = SettingType.Integer,
                    MinValue = "5",
                    MaxValue = "1440",
                    DefaultValue = "30",
                    IsRequired = true,
                    IsActive = true,
                    RequiresRestart = false,
                    CreatedAt = DateTime.UtcNow
                }
            );
        }
    }
}
</artifact>
</artifacts>*/

using Microsoft.EntityFrameworkCore;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Data.Security.Models;
using SabaFone.Backend.Data.Encryption.Models;
using SabaFone.Backend.Data.Vulnerabilities.Models;
using SabaFone.Backend.Data.Backups.Models;

namespace SabaFone.Backend.Data
{
    public class SsasDbContext : DbContext
    {
        public SsasDbContext(DbContextOptions<SsasDbContext> options)
            : base(options)
        {
        }

        // Users Tables
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<UserActivity> UserActivities { get; set; }

        // Security Tables
        public DbSet<SecurityEvent> SecurityEvents { get; set; }
        public DbSet<ThreatIntelligence> ThreatIntelligences { get; set; }
        public DbSet<ThreatIntelligence> ThreatIntelligence { get; set; }
        public DbSet<SecurityPolicy> SecurityPolicies { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<ComplianceFramework> ComplianceFrameworks { get; set; }

        // Encryption Tables
        public DbSet<EncryptionKey> EncryptionKeys { get; set; }

        // Vulnerabilities Tables
        public DbSet<Vulnerability> Vulnerabilities { get; set; }

        // Backup Tables
        public DbSet<BackupJob> BackupJobs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // User Entity Configuration
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);
                entity.HasIndex(e => e.Username).IsUnique();
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Username).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PasswordHash).IsRequired();
                entity.Property(e => e.FullName).HasMaxLength(100);
                entity.Property(e => e.PhoneNumber).HasMaxLength(20);
                entity.Property(e => e.Department).HasMaxLength(50);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.IsLocked).HasDefaultValue(false);
                entity.Property(e => e.MfaEnabled).HasDefaultValue(false);
                entity.Property(e => e.MustChangePassword).HasDefaultValue(false);
            });

            // Role Entity Configuration
            modelBuilder.Entity<Role>(entity =>
            {
                entity.HasKey(e => e.RoleId);
                entity.HasIndex(e => e.Name).IsUnique();
                entity.Property(e => e.Name).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Description).HasMaxLength(200);
                entity.Property(e => e.IsSystem).HasDefaultValue(false);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });

            // UserRole Entity Configuration (Many-to-Many)
            modelBuilder.Entity<UserRole>(entity =>
            {
                entity.HasKey(e => new { e.UserId, e.RoleId });
                
                entity.HasOne(e => e.User)
                    .WithMany(u => u.UserRoles)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
                
                entity.HasOne(e => e.Role)
                    .WithMany(r => r.UserRoles)
                    .HasForeignKey(e => e.RoleId)
                    .OnDelete(DeleteBehavior.Cascade);
                
                entity.Property(e => e.AssignedAt).HasDefaultValueSql("GETUTCDATE()");
            });

            // UserActivity Entity Configuration
            modelBuilder.Entity<UserActivity>(entity =>
            {
                entity.HasKey(e => e.ActivityId);
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.ActivityTime);
                entity.Property(e => e.ActivityType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Description).HasMaxLength(500);
                entity.Property(e => e.IpAddress).HasMaxLength(45);
                entity.Property(e => e.UserAgent).HasMaxLength(500);
                entity.Property(e => e.ActivityTime).HasDefaultValueSql("GETUTCDATE()");
                
                entity.HasOne(e => e.User)
                    .WithMany(u => u.Activities)
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // SecurityEvent Entity Configuration
            modelBuilder.Entity<SecurityEvent>(entity =>
            {
                entity.HasKey(e => e.EventId);
                entity.HasIndex(e => e.EventTime);
                entity.HasIndex(e => e.Severity);
                entity.Property(e => e.EventType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Severity).IsRequired().HasMaxLength(20);
                entity.Property(e => e.Description).HasMaxLength(1000);
                entity.Property(e => e.Source).HasMaxLength(100);
                entity.Property(e => e.SourceIp).HasMaxLength(45);
                entity.Property(e => e.EventTime).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsResolved).HasDefaultValue(false);
                entity.Property(e => e.EventData).HasColumnType("nvarchar(max)");
                
                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // ThreatIntelligence Entity Configuration
            modelBuilder.Entity<ThreatIntelligence>(entity =>
            {
                entity.HasKey(e => e.ThreatId);
                entity.HasIndex(e => e.ThreatType);
                entity.HasIndex(e => e.Severity);
                entity.Property(e => e.ThreatType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.ThreatName).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Description).HasMaxLength(2000);
                entity.Property(e => e.Severity).IsRequired().HasMaxLength(20);
                entity.Property(e => e.Source).HasMaxLength(100);
                entity.Property(e => e.Indicators).HasColumnType("nvarchar(max)");
                entity.Property(e => e.Mitigation).HasMaxLength(2000);
                entity.Property(e => e.DetectedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.IsMitigated).HasDefaultValue(false);
            });

            // SecurityPolicy Entity Configuration
            modelBuilder.Entity<SecurityPolicy>(entity =>
            {
                entity.HasKey(e => e.PolicyId);
                entity.HasIndex(e => e.PolicyName).IsUnique();
                entity.Property(e => e.PolicyName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.PolicyType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Description).HasMaxLength(500);
                entity.Property(e => e.PolicyContent).HasColumnType("nvarchar(max)");
                entity.Property(e => e.Version).IsRequired().HasMaxLength(20);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.IsMandatory).HasDefaultValue(false);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.EnforcementLevel).HasMaxLength(20);
                entity.Property(e => e.ComplianceStatus).HasMaxLength(20);
            });

            // AuditLog Entity Configuration
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.LogId);
                entity.HasIndex(e => e.Timestamp);
                entity.HasIndex(e => e.EventType);
                entity.HasIndex(e => e.UserId);
                entity.Property(e => e.EventType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.EventDescription).HasMaxLength(1000);
                entity.Property(e => e.EntityType).HasMaxLength(50);
                entity.Property(e => e.OldValues).HasColumnType("nvarchar(max)");
                entity.Property(e => e.NewValues).HasColumnType("nvarchar(max)");
                entity.Property(e => e.IpAddress).HasMaxLength(45);
                entity.Property(e => e.UserAgent).HasMaxLength(500);
                entity.Property(e => e.Timestamp).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.Result).HasMaxLength(50);
                entity.Property(e => e.Duration).HasColumnType("decimal(10,2)");
                
                entity.HasOne(e => e.User)
                    .WithMany()
                    .HasForeignKey(e => e.UserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // ComplianceFramework Entity Configuration
            modelBuilder.Entity<ComplianceFramework>(entity =>
            {
                entity.HasKey(e => e.FrameworkId);
                entity.HasIndex(e => e.FrameworkName);
                entity.Property(e => e.FrameworkName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Version).HasMaxLength(20);
                entity.Property(e => e.Description).HasMaxLength(1000);
                entity.Property(e => e.Requirements).HasColumnType("nvarchar(max)");
                entity.Property(e => e.Controls).HasColumnType("nvarchar(max)");
                entity.Property(e => e.ComplianceLevel).HasColumnType("decimal(5,2)");
                entity.Property(e => e.LastAssessmentDate);
                entity.Property(e => e.NextAssessmentDate);
                entity.Property(e => e.Status).HasMaxLength(20);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
            });

            // EncryptionKey Entity Configuration
            modelBuilder.Entity<EncryptionKey>(entity =>
            {
                entity.HasKey(e => e.KeyId);
                entity.HasIndex(e => e.KeyName).IsUnique();
                entity.Property(e => e.KeyName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.KeyType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.Algorithm).IsRequired().HasMaxLength(50);
                entity.Property(e => e.KeySize).IsRequired();
                entity.Property(e => e.KeyValue).IsRequired();
                entity.Property(e => e.KeyMetadata).HasColumnType("nvarchar(max)");
                entity.Property(e => e.Purpose).HasMaxLength(200);
                entity.Property(e => e.Status).HasMaxLength(20);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.ExpiresAt);
                entity.Property(e => e.LastRotatedAt);
                entity.Property(e => e.UsageCount).HasDefaultValue(0);
                
                entity.HasOne(e => e.CreatedByUser)
                    .WithMany()
                    .HasForeignKey(e => e.CreatedBy)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // Vulnerability Entity Configuration
            modelBuilder.Entity<Vulnerability>(entity =>
            {
                entity.HasKey(e => e.VulnerabilityId);
                entity.HasIndex(e => e.Severity);
                entity.HasIndex(e => e.Status);
                entity.HasIndex(e => e.DiscoveredAt);
                entity.Property(e => e.Title).IsRequired().HasMaxLength(200);
                entity.Property(e => e.Description).HasMaxLength(2000);
                entity.Property(e => e.Severity).IsRequired().HasMaxLength(20);
                entity.Property(e => e.Status).IsRequired().HasMaxLength(20);
                entity.Property(e => e.Type).HasMaxLength(50);
                entity.Property(e => e.CVEIdentifier).HasMaxLength(50);
                entity.Property(e => e.CVSSScore).HasColumnType("decimal(3,1)");
                entity.Property(e => e.AffectedSystem).HasMaxLength(200);
                entity.Property(e => e.AffectedComponent).HasMaxLength(200);
                entity.Property(e => e.RemediationPlan).HasMaxLength(2000);
                entity.Property(e => e.RemediationStatus).HasMaxLength(20);
                entity.Property(e => e.RiskScore).HasColumnType("decimal(5,2)");
                entity.Property(e => e.DiscoveredBy).HasMaxLength(100);
                entity.Property(e => e.DiscoveredAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.IsExploitable).HasDefaultValue(false);
                entity.Property(e => e.IsPatched).HasDefaultValue(false);
                entity.Property(e => e.AffectedAssets).HasDefaultValue(0);
                entity.Property(e => e.EstimatedEffort).HasColumnType("decimal(10,2)");
                
                entity.HasOne(e => e.AssignedToUser)
                    .WithMany()
                    .HasForeignKey(e => e.AssignedTo)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // BackupJob Entity Configuration
            modelBuilder.Entity<BackupJob>(entity =>
            {
                entity.HasKey(e => e.JobId);
                entity.HasIndex(e => e.JobName).IsUnique();
                entity.HasIndex(e => e.NextRunTime);
                entity.Property(e => e.JobName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Description).HasMaxLength(500);
                entity.Property(e => e.BackupType).IsRequired().HasMaxLength(50);
                entity.Property(e => e.SourcePath).HasMaxLength(500);
                entity.Property(e => e.DestinationPath).HasMaxLength(500);
                entity.Property(e => e.Schedule).HasMaxLength(100);
                entity.Property(e => e.RetentionDays).HasDefaultValue(30);
                entity.Property(e => e.IsScheduled).HasDefaultValue(false);
                entity.Property(e => e.IsActive).HasDefaultValue(true);
                entity.Property(e => e.CompressionEnabled).HasDefaultValue(true);
                entity.Property(e => e.EncryptionEnabled).HasDefaultValue(true);
                entity.Property(e => e.Status).HasMaxLength(20);
                entity.Property(e => e.LastRunStatus).HasMaxLength(20);
                entity.Property(e => e.BackupSize).HasColumnType("bigint");
                entity.Property(e => e.Duration).HasColumnType("decimal(10,2)");
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.Property(e => e.TotalRuns).HasDefaultValue(0);
                entity.Property(e => e.SuccessfulRuns).HasDefaultValue(0);
                entity.Property(e => e.FailedRuns).HasDefaultValue(0);
                
                entity.HasOne(e => e.CreatedByUser)
                    .WithMany()
                    .HasForeignKey(e => e.CreatedBy)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // Seed initial data
            SeedInitialData(modelBuilder);
        }

        private void SeedInitialData(ModelBuilder modelBuilder)
        {
            // Seed default roles
            var adminRoleId = Guid.NewGuid();
            var userRoleId = Guid.NewGuid();
            
            modelBuilder.Entity<Role>().HasData(
                new Role
                {
                    RoleId = adminRoleId,
                    Name = "Admin",
                    Description = "System Administrator",
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    RoleId = userRoleId,
                    Name = "User",
                    Description = "Standard User",
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    RoleId = Guid.NewGuid(),
                    Name = "SecurityOfficer",
                    Description = "Security Officer",
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    RoleId = Guid.NewGuid(),
                    Name = "Auditor",
                    Description = "System Auditor",
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    RoleId = Guid.NewGuid(),
                    Name = "ComplianceOfficer",
                    Description = "Compliance Officer",
                    IsSystem = true,
                    CreatedAt = DateTime.UtcNow
                }
            );

            // Seed default security policies
            modelBuilder.Entity<SecurityPolicy>().HasData(
                new SecurityPolicy
                {
                    PolicyId = Guid.NewGuid(),
                    PolicyName = "Password Policy",
                    PolicyType = "Authentication",
                    Description = "Defines password requirements and rotation policies",
                    Version = "1.0",
                    IsActive = true,
                    IsMandatory = true,
                    CreatedAt = DateTime.UtcNow,
                    EnforcementLevel = "High",
                    ComplianceStatus = "Active"
                },
                new SecurityPolicy
                {
                    PolicyId = Guid.NewGuid(),
                    PolicyName = "Access Control Policy",
                    PolicyType = "Authorization",
                    Description = "Defines access control and permission management",
                    Version = "1.0",
                    IsActive = true,
                    IsMandatory = true,
                    CreatedAt = DateTime.UtcNow,
                    EnforcementLevel = "High",
                    ComplianceStatus = "Active"
                },
                new SecurityPolicy
                {
                    PolicyId = Guid.NewGuid(),
                    PolicyName = "Data Encryption Policy",
                    PolicyType = "Encryption",
                    Description = "Defines data encryption requirements",
                    Version = "1.0",
                    IsActive = true,
                    IsMandatory = true,
                    CreatedAt = DateTime.UtcNow,
                    EnforcementLevel = "High",
                    ComplianceStatus = "Active"
                }
            );
        }
    }
}