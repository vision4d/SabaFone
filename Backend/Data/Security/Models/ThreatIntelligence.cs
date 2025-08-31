using System;
using System.ComponentModel.DataAnnotations;

namespace SabaFone.Backend.Data.Security.Models
{
    public class ThreatIntelligence
    {
        [Key]
        public Guid ThreatId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(50)]
        public string ThreatType { get; set; }

        [Required]
        [MaxLength(200)]
        public string ThreatName { get; set; }

        [MaxLength(2000)]
        public string Description { get; set; }

        [Required]
        [MaxLength(20)]
        public string Severity { get; set; } // Critical, High, Medium, Low

        [MaxLength(100)]
        public string Source { get; set; }

        public string Indicators { get; set; } // JSON array of indicators
        
        [MaxLength(2000)]
        public string Mitigation { get; set; }

        public string AffectedSystems { get; set; }
        public string AttackVector { get; set; }
        public string ThreatActor { get; set; }
        
        public double? ConfidenceScore { get; set; }
        public double? RiskScore { get; set; }

        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastUpdated { get; set; }
        public DateTime? MitigatedAt { get; set; }

        public bool IsActive { get; set; } = true;
        public bool IsMitigated { get; set; } = false;
        
        public Guid? MitigatedBy { get; set; }
    }
}