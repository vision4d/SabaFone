//1️⃣ Data/Users/Models/User.cs
/*<artifacts>
<artifact identifier="user-model" type="application/vnd.ant.code" language="csharp" title="Data/Users/Models/User.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/Users/Models/User.cs
// نموذج المستخدم - شركة سبأفون
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend.Data.Users.Models
{
/// <summary>
/// نموذج المستخدم الأساسي
/// </summary>
[Table("Users")]
[Index(nameof(Username), IsUnique = true)]
[Index(nameof(Email), IsUnique = true)]
[Index(nameof(EmployeeId), IsUnique = true)]
public class User
{
[Key]
[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
public Guid UserId { get; set; }
[Required]
    [StringLength(50, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    [EmailAddress]
    [StringLength(255)]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string PasswordHash { get; set; } = string.Empty;
    
    [StringLength(255)]
    public string? PasswordSalt { get; set; }
    
    [StringLength(50)]
    public string? EmployeeId { get; set; }
    
    // Personal Information
    [Required]
    [StringLength(100)]
    public string FirstName { get; set; } = string.Empty;
    
    [Required]
    [StringLength(100)]
    public string LastName { get; set; } = string.Empty;
    
    [StringLength(100)]
    public string? MiddleName { get; set; }
    
    [StringLength(100)]
    public string? DisplayName { get; set; }
    
    [Phone]
    [StringLength(20)]
    public string? PhoneNumber { get; set; }
    
    [StringLength(20)]
    public string? MobileNumber { get; set; }
    
    [StringLength(100)]
    public string? Department { get; set; }
    
    [StringLength(100)]
    public string? JobTitle { get; set; }
    
    [StringLength(100)]
    public string? Location { get; set; }
    
    [StringLength(100)]
    public string? ManagerId { get; set; }
    
    // Account Status
    public UserStatus Status { get; set; } = UserStatus.Pending;
    
    public bool IsActive { get; set; } = true;
    
    public bool IsLocked { get; set; } = false;
    
    public DateTime? LockedUntil { get; set; }
    
    public string? LockReason { get; set; }
    
    public bool EmailVerified { get; set; } = false;
    
    public DateTime? EmailVerifiedAt { get; set; }
    
    public bool PhoneVerified { get; set; } = false;
    
    public DateTime? PhoneVerifiedAt { get; set; }
    
    // Security Settings
    public bool MfaEnabled { get; set; } = false;
    
    [StringLength(255)]
    public string? MfaSecret { get; set; }
    
    public MfaType? MfaType { get; set; }
    
    [StringLength(500)]
    public string? MfaBackupCodes { get; set; }
    
    public bool PasswordExpired { get; set; } = false;
    
    public DateTime? PasswordChangedAt { get; set; }
    
    public DateTime? PasswordExpiresAt { get; set; }
    
    public int FailedLoginAttempts { get; set; } = 0;
    
    public DateTime? LastFailedLoginAt { get; set; }
    
    public bool RequirePasswordChange { get; set; } = false;
    
    // Access Information
    public DateTime? LastLoginAt { get; set; }
    
    [StringLength(50)]
    public string? LastLoginIp { get; set; }
    
    [StringLength(500)]
    public string? LastLoginUserAgent { get; set; }
    
    public int TotalLogins { get; set; } = 0;
    
    [StringLength(100)]
    public string? PreferredLanguage { get; set; } = "ar";
    
    [StringLength(100)]
    public string? TimeZone { get; set; } = "Asia/Aden";
    
    // Permissions and Roles
    public string? Permissions { get; set; } // JSON serialized permissions
    
    public string? CustomClaims { get; set; } // JSON serialized claims
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public DateTime? DeletedAt { get; set; }
    
    [StringLength(100)]
    public string? DeletedBy { get; set; }
    
    public bool IsDeleted { get; set; } = false;
    
    // Profile Picture
    [StringLength(500)]
    public string? ProfilePictureUrl { get; set; }
    
    [StringLength(255)]
    public string? ProfilePictureHash { get; set; }
    
    // Additional Security
    [StringLength(1000)]
    public string? AllowedIpAddresses { get; set; } // JSON array
    
    [StringLength(1000)]
    public string? BlockedIpAddresses { get; set; } // JSON array
    
    public bool RestrictIpAccess { get; set; } = false;
    
    // API Access
    [StringLength(255)]
    public string? ApiKey { get; set; }
    
    public DateTime? ApiKeyExpiresAt { get; set; }
    
    public bool ApiAccessEnabled { get; set; } = false;
    
    // Notification Preferences
    public bool EmailNotifications { get; set; } = true;
    
    public bool SmsNotifications { get; set; } = false;
    
    public bool PushNotifications { get; set; } = true;
    
    public string? NotificationSettings { get; set; } // JSON
    
    // Navigation Properties
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<UserSession> Sessions { get; set; } = new List<UserSession>();
    public virtual ICollection<UserLoginAttempt> LoginAttempts { get; set; } = new List<UserLoginAttempt>();
    public virtual ICollection<UserActivity> Activities { get; set; } = new List<UserActivity>();
    public virtual ICollection<UserToken> Tokens { get; set; } = new List<UserToken>();
    public virtual ICollection<UserPermission> UserPermissions { get; set; } = new List<UserPermission>();
    public virtual ICollection<UserDevice> Devices { get; set; } = new List<UserDevice>();
    public virtual ICollection<UserNotification> Notifications { get; set; } = new List<UserNotification>();
    
    // Computed Properties
    [NotMapped]
    public string FullName => $"{FirstName} {LastName}".Trim();
    
    [NotMapped]
    public bool IsAccountLocked => IsLocked || (LockedUntil.HasValue && LockedUntil.Value > DateTime.UtcNow);
    
    [NotMapped]
    public bool CanLogin => IsActive && !IsDeleted && !IsAccountLocked && EmailVerified;
}

public enum UserStatus
{
    Pending = 0,
    Active = 1,
    Inactive = 2,
    Suspended = 3,
    Locked = 4,
    Expired = 5,
    Archived = 6
}

public enum MfaType
{
    None = 0,
    Totp = 1,
    Sms = 2,
    Email = 3,
    Hardware = 4,
    Biometric = 5
}}
</artifact>
</artifacts>*/
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace SabaFone.Backend.Data.Users.Models
{
    public class User
    {
        [Key]
        public Guid UserId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(50)]
        public string Username { get; set; } 
        
        [Required]
        [EmailAddress]
        [MaxLength(100)]
        public string Email { get; set; } 

        [Required]
        public string PasswordHash { get; set; } 

        [MaxLength(100)]
        public string FullName { get; set; }

        [Phone]
        [MaxLength(20)]
        public string PhoneNumber { get; set; }

        [MaxLength(50)]
        public string Department { get; set; }

        public bool IsActive { get; set; } = true;
        public bool IsLocked { get; set; } = false;
        public string LockReason { get; set; }
        public DateTime? LockedUntil { get; set; }

        public bool MfaEnabled { get; set; } = false;
        public string MfaSecret { get; set; } 
        public string MfaBackupCodes { get; set; }

        public bool MustChangePassword { get; set; } = false;
        public DateTime? PasswordExpiresAt { get; set; }
        public DateTime? PasswordResetAt { get; set; }
        public string PasswordResetToken { get; set; }
        public DateTime? PasswordResetTokenExpires { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LastFailedLogin { get; set; }
        public DateTime? LastLogin { get; set; }
        public string LastLoginIp { get; set; }

        public string RefreshToken { get; set; }
        public DateTime? RefreshTokenExpires { get; set; }
        public List<string> Permissions { get; set; } = new List<string>();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public Guid? UpdatedBy { get; set; }

        // Navigation properties
        public virtual ICollection<UserRole> UserRoles { get; set; } = new HashSet<UserRole>();
        public virtual ICollection<UserActivity> Activities { get; set; } = new HashSet<UserActivity>();
    }
}