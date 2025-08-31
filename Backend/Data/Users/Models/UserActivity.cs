using System;
using System.ComponentModel.DataAnnotations;

namespace SabaFone.Backend.Data.Users.Models
{
    public class UserActivity
    {
        [Key]
        public Guid ActivityId { get; set; } = Guid.NewGuid();

        [Required]
        public Guid UserId { get; set; }

        [Required]
        [MaxLength(50)]
        public string ActivityType { get; set; }

        [MaxLength(500)]
        public string Description { get; set; }

        [MaxLength(45)]
        public string IpAddress { get; set; }

        [MaxLength(500)]
        public string UserAgent { get; set; }

        public string SessionId { get; set; }
        public string RequestPath { get; set; }
        public string RequestMethod { get; set; }
        public int? ResponseCode { get; set; }
        public string ResponseStatus { get; set; }
        
        public DateTime ActivityTime { get; set; } = DateTime.UtcNow;

        // Navigation properties
        public virtual User User { get; set; }
    }
}