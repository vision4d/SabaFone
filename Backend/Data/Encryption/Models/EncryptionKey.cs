using System;
using System.ComponentModel.DataAnnotations;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Data.Encryption.Models
{
    public class EncryptionKey
    {
        [Key]
        public Guid KeyId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string KeyName { get; set; }

        [Required]
        [MaxLength(50)]
        public string KeyType { get; set; } // Symmetric, Asymmetric, Hybrid

        [Required]
        [MaxLength(50)]
        public string Algorithm { get; set; } // AES, RSA, etc.

        [Required]
        public int KeySize { get; set; } // 128, 256, 2048, 4096

        [Required]
        public byte[] KeyValue { get; set; } // Encrypted key value

        public byte[] PublicKey { get; set; } // For asymmetric keys
        public byte[] PrivateKey { get; set; } // For asymmetric keys (encrypted)

        public string KeyMetadata { get; set; } // JSON metadata

        [MaxLength(200)]
        public string Purpose { get; set; }

        [MaxLength(20)]
        public string Status { get; set; } // Active, Rotated, Expired, Revoked

        public bool IsActive { get; set; } = true;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ExpiresAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public DateTime? LastRotatedAt { get; set; }
        public DateTime? RevokedAt { get; set; }

        public int UsageCount { get; set; } = 0;
        public string RotationSchedule { get; set; }
        
        public Guid? CreatedBy { get; set; }
        public Guid? RevokedBy { get; set; }
        public string RevocationReason { get; set; }

        // Navigation properties
        public virtual Users.Models.User CreatedByUser { get; set; }
    }
}