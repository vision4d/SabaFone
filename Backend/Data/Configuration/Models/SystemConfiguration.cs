//4️⃣ Data/Configuration/Models/SystemConfiguration.cs

/*<artifacts>
<artifact identifier="system-configuration-model" type="application/vnd.ant.code" language="csharp" title="Data/Configuration/Models/SystemConfiguration.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/Configuration/Models/SystemConfiguration.cs
// نموذج إعدادات النظام - شركة سبأفون*/
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend.Data.Configuration.Models
{
/// <summary>
/// إعدادات النظام
/// </summary>
[Table("SystemSettings")]
[Index(nameof(SettingKey), IsUnique = true)]
[Index(nameof(Category))]
[Index(nameof(IsActive))]
public class SystemSetting
{
[Key]
[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
public Guid SettingId { get; set; }
[Required]
    [StringLength(255)]
    public string SettingKey { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string SettingName { get; set; } = string.Empty;
    
    [Required]
    public string SettingValue { get; set; } = string.Empty;
    
    [StringLength(500)]
    public string? Description { get; set; }
    
    [Required]
    [StringLength(100)]
    public string Category { get; set; } = string.Empty;
    
    [StringLength(100)]
    public string? SubCategory { get; set; }
    
    public SettingType DataType { get; set; } = SettingType.String;
    
    // Validation
    public string? ValidationRules { get; set; } // JSON
    
    [StringLength(500)]
    public string? ValidationPattern { get; set; } // Regex
    
    public string? MinValue { get; set; }
    
    public string? MaxValue { get; set; }
    
    public string? AllowedValues { get; set; } // JSON array
    
    public string? DefaultValue { get; set; }
    
    public bool IsRequired { get; set; } = false;
    
    // Security
    public bool IsEncrypted { get; set; } = false;
    
    public bool IsSensitive { get; set; } = false;
    
    public AccessLevel AccessLevel { get; set; } = AccessLevel.Admin;
    
    public bool RequiresRestart { get; set; } = false;
    
    public bool RequiresApproval { get; set; } = false;
    
    // Status
    public bool IsActive { get; set; } = true;
    
    public bool IsReadOnly { get; set; } = false;
    
    public bool IsSystem { get; set; } = false;
    
    public bool IsDeprecated { get; set; } = false;
    
    [StringLength(50)]
    public string? DeprecatedVersion { get; set; }
    
    // Environment
    public string? ApplicableEnvironments { get; set; } // JSON array
    
    public bool IsEnvironmentSpecific { get; set; } = false;
    
    // UI Display
    [StringLength(255)]
    public string? DisplayName { get; set; }
    
    [StringLength(255)]
    public string? ArabicDisplayName { get; set; }
    
    [StringLength(500)]
    public string? HelpText { get; set; }
    
    [StringLength(500)]
    public string? ArabicHelpText { get; set; }
    
    public int DisplayOrder { get; set; } = 100;
    
    [StringLength(50)]
    public string? UIControlType { get; set; }
    
    // Audit
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public DateTime? LastAccessedAt { get; set; }
    
    // Dependencies
    public string? DependsOn { get; set; } // JSON array of setting keys
    
    public string? AffectsSettings { get; set; } // JSON array of setting keys
    
    // Metadata
    public string? Tags { get; set; } // JSON array
    
    public string? CustomAttributes { get; set; } // JSON
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    public virtual ICollection<SettingHistory> History { get; set; } = new List<SettingHistory>();
}

/// <summary>
/// سجل تغييرات الإعدادات
/// </summary>
[Table("SettingHistory")]
[Index(nameof(SettingId))]
[Index(nameof(ChangedAt))]
public class SettingHistory
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid HistoryId { get; set; }
    
    [Required]
    public Guid SettingId { get; set; }
    
    [Required]
    public string OldValue { get; set; } = string.Empty;
    
    [Required]
    public string NewValue { get; set; } = string.Empty;
    
    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(100)]
    public string ChangedBy { get; set; } = string.Empty;
    
    [StringLength(500)]
    public string? ChangeReason { get; set; }
    
    [StringLength(50)]
    public string? IpAddress { get; set; }
    
    [StringLength(100)]
    public string? SessionId { get; set; }
    
    // Approval
    public bool RequiredApproval { get; set; } = false;
    
    public bool WasApproved { get; set; } = false;
    
    public DateTime? ApprovedAt { get; set; }
    
    [StringLength(100)]
    public string? ApprovedBy { get; set; }
    
    // Rollback
    public bool WasRolledBack { get; set; } = false;
    
    public DateTime? RolledBackAt { get; set; }
    
    [StringLength(100)]
    public string? RolledBackBy { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(SettingId))]
    public virtual SystemSetting Setting { get; set; } = null!;
}

/// <summary>
/// إعدادات الإشعارات
/// </summary>
[Table("NotificationSettings")]
[Index(nameof(UserId))]
[Index(nameof(Channel))]
public class NotificationSetting
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid Id { get; set; }
    
    public Guid? UserId { get; set; }
    
    [StringLength(100)]
    public string? RoleName { get; set; }
    
    [Required]
    public NotificationChannel Channel { get; set; }
    
    public bool IsEnabled { get; set; } = true;
    
    // Channel Configuration
    [StringLength(255)]
    public string? EmailAddress { get; set; }
    
    [StringLength(20)]
    public string? PhoneNumber { get; set; }
    
    [StringLength(500)]
    public string? WebhookUrl { get; set; }
    
    [StringLength(255)]
    public string? SlackChannel { get; set; }
    
    [StringLength(255)]
    public string? TeamsChannel { get; set; }
    
    // Event Types
    public string? EnabledEventTypes { get; set; } // JSON array
    
    public string? DisabledEventTypes { get; set; } // JSON array
    
    // Severity Filtering
    public NotificationSeverity MinimumSeverity { get; set; } = NotificationSeverity.Medium;
    
    public bool IncludeLowSeverity { get; set; } = false;
    
    public bool IncludeInfoOnly { get; set; } = false;
    
    // Schedule
    public bool ImmediateDelivery { get; set; } = true;
    
    public bool BatchNotifications { get; set; } = false;
    
    public int BatchIntervalMinutes { get; set; } = 60;
    
    public string? QuietHours { get; set; } // JSON: {start: "22:00", end: "08:00"}
    
    public string? ActiveDays { get; set; } // JSON array of days
    
    // Format
    public NotificationFormat Format { get; set; } = NotificationFormat.HTML;
    
    [StringLength(100)]
    public string? Language { get; set; } = "ar";
    
    public bool IncludeDetails { get; set; } = true;
    
    public bool IncludeActionLinks { get; set; } = true;
    
    // Limits
    public int MaxNotificationsPerHour { get; set; } = 100;
    
    public int MaxNotificationsPerDay { get; set; } = 1000;
    
    // Templates
    [StringLength(255)]
    public string? CustomTemplate { get; set; }
    
    public string? TemplateVariables { get; set; } // JSON
    
    // Status
    public bool IsActive { get; set; } = true;
    
    public DateTime? SuspendedUntil { get; set; }
    
    [StringLength(500)]
    public string? SuspensionReason { get; set; }
    
    // Statistics
    public int NotificationsSent { get; set; } = 0;
    
    public DateTime? LastNotificationAt { get; set; }
    
    public int FailedAttempts { get; set; } = 0;
    
    public DateTime? LastFailureAt { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
}

/// <summary>
/// سياسات كلمات المرور
/// </summary>
[Table("PasswordPolicies")]
[Index(nameof(PolicyName), IsUnique = true)]
[Index(nameof(IsActive))]
public class PasswordPolicy
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid PolicyId { get; set; }
    
    [Required]
    [StringLength(255)]
    public string PolicyName { get; set; } = string.Empty;
    
    [Required]
    public string Description { get; set; } = string.Empty;
    
    public bool IsActive { get; set; } = true;
    
    public bool IsDefault { get; set; } = false;
    
    // Length Requirements
    public int MinimumLength { get; set; } = 8;
    
    public int MaximumLength { get; set; } = 128;
    
    // Complexity Requirements
    public bool RequireUppercase { get; set; } = true;
    
    public int MinimumUppercase { get; set; } = 1;
    
    public bool RequireLowercase { get; set; } = true;
    
    public int MinimumLowercase { get; set; } = 1;
    
    public bool RequireNumbers { get; set; } = true;
    
    public int MinimumNumbers { get; set; } = 1;
    
    public bool RequireSpecialCharacters { get; set; } = true;
    
    public int MinimumSpecialCharacters { get; set; } = 1;
    
    [StringLength(100)]
    public string? AllowedSpecialCharacters { get; set; }
    
    public bool RequireUniqueCharacters { get; set; } = false;
    
    public int MinimumUniqueCharacters { get; set; } = 4;
    
    // Restrictions
    public bool DisallowUsername { get; set; } = true;
    
    public bool DisallowEmail { get; set; } = true;
    
    public bool DisallowPersonalInfo { get; set; } = true;
    
    public bool DisallowCommonPasswords { get; set; } = true;
    
    public bool DisallowDictionaryWords { get; set; } = true;
    
    public bool DisallowSequentialCharacters { get; set; } = true;
    
    public int MaxSequentialCharacters { get; set; } = 3;
    
    public bool DisallowRepeatingCharacters { get; set; } = true;
    
    public int MaxRepeatingCharacters { get; set; } = 3;
    
    // History
    public bool EnforceHistory { get; set; } = true;
    
    public int PasswordHistoryCount { get; set; } = 12;
    
    public int MinimumPasswordAge { get; set; } = 1; // Days
    
    // Expiration
    public bool PasswordExpires { get; set; } = true;
    
    public int PasswordExpirationDays { get; set; } = 90;
    
    public int PasswordExpirationWarningDays { get; set; } = 14;
    
    public bool AllowPasswordExtension { get; set; } = false;
    
    public int MaxPasswordExtensionDays { get; set; } = 30;
    
    // Account Lockout
    public bool EnableAccountLockout { get; set; } = true;
    
    public int MaxFailedAttempts { get; set; } = 5;
    
    public int LockoutDurationMinutes { get; set; } = 30;
    
    public int ResetFailedAttemptsAfterMinutes { get; set; } = 15;
    
    // Multi-Factor Authentication
    public bool RequireMFA { get; set; } = false;
    
    public string? MFAExemptRoles { get; set; } // JSON array
    
    public string? MFARequiredForActions { get; set; } // JSON array
    
    // Password Recovery
    public bool AllowPasswordReset { get; set; } = true;
    
    public int PasswordResetTokenValidityMinutes { get; set; } = 60;
    
    public bool RequireSecurityQuestions { get; set; } = false;
    
    public int MinimumSecurityQuestions { get; set; } = 3;
    
    // Applicability
    public string? ApplicableRoles { get; set; } // JSON array
    
    public string? ExemptUsers { get; set; } // JSON array
    
    // Compliance
    public string? ComplianceStandards { get; set; } // JSON array
    
    public bool MeetsNIST { get; set; } = false;
    
    public bool MeetsISO27001 { get; set; } = false;
    
    public bool MeetsPCIDSS { get; set; } = false;
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public DateTime? LastReviewedAt { get; set; }
    
    [StringLength(100)]
    public string? ReviewedBy { get; set; }
    
    public string? Notes { get; set; }
}

/// <summary>
/// قوالب الإعدادات
/// </summary>
[Table("ConfigurationTemplates")]
[Index(nameof(TemplateName), IsUnique = true)]
public class ConfigurationTemplate
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid TemplateId { get; set; }
    
    [Required]
    [StringLength(255)]
    public string TemplateName { get; set; } = string.Empty;
    
    [Required]
    public string Description { get; set; } = string.Empty;
    
    [Required]
    [StringLength(100)]
    public string Category { get; set; } = string.Empty;
    
    public TemplateType Type { get; set; }
    
    [Required]
    public string Configuration { get; set; } = "{}"; // JSON
    
    // Version
    [StringLength(50)]
    public string Version { get; set; } = "1.0.0";
    
    public bool IsLatestVersion { get; set; } = true;
    
    public Guid? ParentTemplateId { get; set; }
    
    // Applicability
    public string? ApplicableEnvironments { get; set; } // JSON array
    
    public string? ApplicableRoles { get; set; } // JSON array
    
    public string? Prerequisites { get; set; } // JSON array
    
    // Validation
    public string? ValidationRules { get; set; } // JSON
    
    public bool IsValidated { get; set; } = false;
    
    public DateTime? ValidatedAt { get; set; }
    
    [StringLength(100)]
    public string? ValidatedBy { get; set; }
    
    // Usage
    public int UsageCount { get; set; } = 0;
    
    public DateTime? LastUsedAt { get; set; }
    
    public double AverageRating { get; set; } = 0;
    
    public int RatingCount { get; set; } = 0;
    
    // Status
    public bool IsActive { get; set; } = true;
    
    public bool IsPublic { get; set; } = false;
    
    public bool IsApproved { get; set; } = false;
    
    public DateTime? ApprovedAt { get; set; }
    
    [StringLength(100)]
    public string? ApprovedBy { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public string? Tags { get; set; } // JSON array
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(ParentTemplateId))]
    public virtual ConfigurationTemplate? ParentTemplate { get; set; }
    
    public virtual ICollection<ConfigurationTemplate> ChildTemplates { get; set; } = new List<ConfigurationTemplate>();
}

// Enums
public enum SettingType
{
    String = 1,
    Integer = 2,
    Decimal = 3,
    Boolean = 4,
    DateTime = 5,
    JSON = 6,
    XML = 7,
    Binary = 8,
    List = 9,
    Dictionary = 10
}

public enum AccessLevel
{
    Public = 1,
    User = 2,
    PowerUser = 3,
    Admin = 4,
    SuperAdmin = 5,
    System = 6
}

public enum NotificationChannel
{
    Email = 1,
    SMS = 2,
    PushNotification = 3,
    InApp = 4,
    Webhook = 5,
    Slack = 6,
    Teams = 7,
    Telegram = 8,
    WhatsApp = 9
}

public enum NotificationSeverity
{
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
    Emergency = 6
}

public enum NotificationFormat
{
    PlainText = 1,
    HTML = 2,
    Markdown = 3,
    JSON = 4,
    XML = 5
}

public enum TemplateType
{
    System = 1,
    Security = 2,
    Network = 3,
    Application = 4,
    Database = 5,
    Backup = 6,
    Monitoring = 7,
    Custom = 8
}}
/*</artifact>
</artifacts>*/