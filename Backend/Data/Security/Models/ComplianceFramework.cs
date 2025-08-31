using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SabaFone.Backend.Data.Security.Models
{
    public class ComplianceFramework
    {
        [Key]
        public Guid FrameworkId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string FrameworkName { get; set; }

        [MaxLength(20)]
        public string Version { get; set; }

        [MaxLength(1000)]
        public string Description { get; set; }

        public string Requirements { get; set; } // JSON array
        public string Controls { get; set; } // JSON array

        [Column(TypeName = "decimal(5,2)")]
        public decimal? ComplianceLevel { get; set; } // Percentage

        public DateTime? LastAssessmentDate { get; set; }
        public DateTime? NextAssessmentDate { get; set; }

        [MaxLength(20)]
        public string Status { get; set; } // Active, Pending, Expired

        public string AssessmentResults { get; set; } // JSON
        public string Gaps { get; set; } // JSON array
        public string RemediationPlans { get; set; } // JSON array
        public string Evidence { get; set; } // JSON array of evidence links

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public Guid? UpdatedBy { get; set; }
        public Guid? AssessedBy { get; set; }
    }
}