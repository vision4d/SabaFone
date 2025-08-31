using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SabaFone.Backend.Data.Security.Models
{
    public class AuditLog
    {
        [Key]
        public Guid LogId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(50)]
        public string EventType { get; set; }

        [MaxLength(1000)]
        public string EventDescription { get; set; }

        [MaxLength(50)]
        public string EntityType { get; set; }

        public Guid? EntityId { get; set; }

        public string OldValues { get; set; } // JSON
        public string NewValues { get; set; } // JSON

        [MaxLength(45)]
        public string IpAddress { get; set; }

        [MaxLength(500)]
        public string UserAgent { get; set; }

        public string SessionId { get; set; }
        public string RequestId { get; set; }

        [MaxLength(50)]
        public string Result { get; set; } // Success, Failed, Error

        [Column(TypeName = "decimal(10,2)")]
        public decimal? Duration { get; set; } // in milliseconds

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public Guid? UserId { get; set; }

        // Navigation properties
        public virtual Users.Models.User User { get; set; }
    }
}