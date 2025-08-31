using System;
using System.ComponentModel.DataAnnotations;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Data.Security.Models
{
    public class SecurityPolicy
    {
        [Key]
        public Guid PolicyId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string PolicyName { get; set; }

        [Required]
        [MaxLength(50)]
        public string PolicyType { get; set; }

        [MaxLength(500)]
        public string Description { get; set; }

        public string PolicyContent { get; set; } // JSON or structured content

        [Required]
        [MaxLength(20)]
        public string Version { get; set; }

        public bool IsActive { get; set; } = true;
        public bool IsMandatory { get; set; } = false;

        [MaxLength(20)]
        public string EnforcementLevel { get; set; } // High, Medium, Low

        [MaxLength(20)]
        public string ComplianceStatus { get; set; } // Active, Pending, Expired

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public DateTime? EffectiveFrom { get; set; }
        public DateTime? ExpiresAt { get; set; }
        
        public Guid? CreatedBy { get; set; }
        public Guid? UpdatedBy { get; set; }
        public Guid? ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
    }
}