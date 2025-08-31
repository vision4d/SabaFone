//2️⃣ Data/Users/Models/UserRole.cs

/*<artifacts>
<artifact identifier="user-role-model" type="application/vnd.ant.code" language="csharp" title="Data/Users/Models/UserRole.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/Users/Models/UserRole.cs
// نموذج دور المستخدم - شركة سبأفون
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend.Data.Users.Models
{
/// <summary>
/// نموذج الأدوار
/// </summary>
[Table("Roles")]
[Index(nameof(RoleName), IsUnique = true)]
public class Role
{
[Key]
[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
public Guid RoleId { get; set; }
[Required]
    [StringLength(50)]
    public string RoleName { get; set; } = string.Empty;
    
    [StringLength(255)]
    public string? Description { get; set; }
    
    [StringLength(255)]
    public string? ArabicName { get; set; }
    
    [StringLength(500)]
    public string? ArabicDescription { get; set; }
    
    public RoleType Type { get; set; } = RoleType.Custom;
    
    public int Priority { get; set; } = 100;
    
    public bool IsActive { get; set; } = true;
    
    public bool IsSystem { get; set; } = false;
    
    public bool IsDeletable { get; set; } = true;
    
    // Permissions (JSON)
    public string? Permissions { get; set; }
    
    // Hierarchy
    public Guid? ParentRoleId { get; set; }
    
    [ForeignKey(nameof(ParentRoleId))]
    public virtual Role? ParentRole { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    // Navigation Properties
    public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    public virtual ICollection<Role> ChildRoles { get; set; } = new List<Role>();
}

/// <summary>
/// علاقة المستخدم بالدور
/// </summary>
[Table("UserRoles")]
[Index(nameof(UserId), nameof(RoleId), IsUnique = true)]
public class UserRole
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid UserRoleId { get; set; }
    
    [Required]
    public Guid UserId { get; set; }
    
    [Required]
    public Guid RoleId { get; set; }
    
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? AssignedBy { get; set; }
    
    public DateTime? ExpiresAt { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    [StringLength(500)]
    public string? Notes { get; set; }
    
    // Delegation
    public bool IsDelegated { get; set; } = false;
    
    public Guid? DelegatedFrom { get; set; }
    
    public DateTime? DelegationStart { get; set; }
    
    public DateTime? DelegationEnd { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(UserId))]
    public virtual User User { get; set; } = null!;
    
    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;
}

/// <summary>
/// الصلاحيات
/// </summary>
[Table("Permissions")]
[Index(nameof(PermissionName), IsUnique = true)]
public class Permission
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid PermissionId { get; set; }
    
    [Required]
    [StringLength(100)]
    public string PermissionName { get; set; } = string.Empty;
    
    [StringLength(255)]
    public string? Description { get; set; }
    
    [StringLength(255)]
    public string? ArabicName { get; set; }
    
    [StringLength(500)]
    public string? ArabicDescription { get; set; }
    
    [Required]
    [StringLength(50)]
    public string Category { get; set; } = string.Empty;
    
    [Required]
    [StringLength(50)]
    public string Resource { get; set; } = string.Empty;
    
    [Required]
    [StringLength(50)]
    public string Action { get; set; } = string.Empty;
    
    public bool IsActive { get; set; } = true;
    
    public bool IsSystem { get; set; } = false;
    
    // Risk Level
    public RiskLevel Risk { get; set; } = RiskLevel.Low;
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation Properties
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    public virtual ICollection<UserPermission> UserPermissions { get; set; } = new List<UserPermission>();
}

/// <summary>
/// صلاحيات الدور
/// </summary>
[Table("RolePermissions")]
[Index(nameof(RoleId), nameof(PermissionId), IsUnique = true)]
public class RolePermission
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid RolePermissionId { get; set; }
    
    [Required]
    public Guid RoleId { get; set; }
    
    [Required]
    public Guid PermissionId { get; set; }
    
    public bool IsGranted { get; set; } = true;
    
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? GrantedBy { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(RoleId))]
    public virtual Role Role { get; set; } = null!;
    
    [ForeignKey(nameof(PermissionId))]
    public virtual Permission Permission { get; set; } = null!;
}

/// <summary>
/// صلاحيات المستخدم المباشرة
/// </summary>
[Table("UserPermissions")]
[Index(nameof(UserId), nameof(PermissionId), IsUnique = true)]
public class UserPermission
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid UserPermissionId { get; set; }
    
    [Required]
    public Guid UserId { get; set; }
    
    [Required]
    public Guid PermissionId { get; set; }
    
    public bool IsGranted { get; set; } = true;
    
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? GrantedBy { get; set; }
    
    public DateTime? ExpiresAt { get; set; }
    
    [StringLength(500)]
    public string? Reason { get; set; }
    
    // Override role permissions
    public bool OverridesRole { get; set; } = false;
    
    // Navigation Properties
    [ForeignKey(nameof(UserId))]
    public virtual User User { get; set; } = null!;
    
    [ForeignKey(nameof(PermissionId))]
    public virtual Permission Permission { get; set; } = null!;
}

public enum RoleType
{
    System = 0,
    Predefined = 1,
    Custom = 2,
    Temporary = 3
}

public enum RiskLevel
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}}
</artifact>
</artifacts>*/

using System;
using System.ComponentModel.DataAnnotations;

namespace SabaFone.Backend.Data.Users.Models
{
    public class UserRole
    {
        [Required]
        public Guid UserId { get; set; }
        
        [Required]
        public Guid RoleId { get; set; }

        public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
        public Guid? AssignedBy { get; set; }

        // Navigation properties
        public virtual User User { get; set; }
        public virtual Role Role { get; set; }
    }
}