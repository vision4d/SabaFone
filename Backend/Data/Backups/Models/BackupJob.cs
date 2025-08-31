//️⃣ Data/Backups/Models/Backup.cs

/*<artifacts>
<artifact identifier="backup-model" type="application/vnd.ant.code" language="csharp" title="Data/Backups/Models/Backup.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/Backups/Models/Backup.cs
// نموذج النسخ الاحتياطية - شركة سبأفون
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend.Data.Backups.Models
{
/// <summary>
/// وظائف النسخ الاحتياطي
/// </summary>
[Table("BackupJobs")]
[Index(nameof(JobName), IsUnique = true)]
[Index(nameof(Status))]
[Index(nameof(ScheduledAt))]
public class BackupJob
{
[Key]
[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
public Guid JobId { get; set; }
[Required]
    [StringLength(255)]
    public string JobName { get; set; } = string.Empty;
    
    [Required]
    public string Description { get; set; } = string.Empty;
    
    public BackupType Type { get; set; }
    
    public BackupScope Scope { get; set; }
    
    public JobStatus Status { get; set; } = JobStatus.Pending;
    
    // Schedule
    public bool IsScheduled { get; set; } = false;
    
    [StringLength(100)]
    public string? Schedule { get; set; } // Cron expression
    
    public DateTime? ScheduledAt { get; set; }
    
    public DateTime? NextRunTime { get; set; }
    
    public DateTime? LastRunTime { get; set; }
    
    // Configuration
    public string BackupSources { get; set; } = "[]"; // JSON array
    
    public string? ExcludedItems { get; set; } // JSON array
    
    public CompressionType Compression { get; set; } = CompressionType.GZip;
    
    public int CompressionLevel { get; set; } = 6;
    
    public EncryptionType Encryption { get; set; } = EncryptionType.AES256;
    
    [StringLength(255)]
    public string? EncryptionKeyId { get; set; }
    
    public bool EnableDeduplication { get; set; } = true;
    
    public bool EnableIncremental { get; set; } = true;
    
    // Storage
    [Required]
    [StringLength(500)]
    public string PrimaryStorageLocation { get; set; } = string.Empty;
    
    [StringLength(500)]
    public string? SecondaryStorageLocation { get; set; }
    
    [StringLength(500)]
    public string? OffsiteStorageLocation { get; set; }
    
    public StorageType StorageType { get; set; }
    
    public int RetentionDays { get; set; } = 30;
    
    public int MaxBackupCount { get; set; } = 10;
    
    // Performance
    public int MaxParallelStreams { get; set; } = 4;
    
    public int BufferSizeMB { get; set; } = 64;
    
    public int NetworkBandwidthMbps { get; set; } = 0; // 0 = unlimited
    
    public int Priority { get; set; } = 5; // 1-10
    
    // Verification
    public bool VerifyAfterBackup { get; set; } = true;
    
    public VerificationType VerificationType { get; set; } = VerificationType.Checksum;
    
    public bool AutoTestRestore { get; set; } = false;
    
    public int TestRestoreFrequencyDays { get; set; } = 30;
    
    // Notifications
    public bool NotifyOnSuccess { get; set; } = false;
    
    public bool NotifyOnFailure { get; set; } = true;
    
    public string? NotificationRecipients { get; set; } // JSON array
    
    // Statistics
    public int TotalRuns { get; set; } = 0;
    
    public int SuccessfulRuns { get; set; } = 0;
    
    public int FailedRuns { get; set; } = 0;
    
    public long TotalDataBackedUpBytes { get; set; } = 0;
    
    public long AverageBackupSizeBytes { get; set; } = 0;
    
    public int AverageBackupTimeMinutes { get; set; } = 0;
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public bool IsDeleted { get; set; } = false;
    
    public DateTime? DeletedAt { get; set; }
    
    // Additional Settings
    public string? PreBackupScript { get; set; }
    
    public string? PostBackupScript { get; set; }
    
    public string? Tags { get; set; } // JSON array
    
    public string? CustomSettings { get; set; } // JSON
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    public virtual ICollection<BackupHistory> BackupHistories { get; set; } = new List<BackupHistory>();
    public virtual ICollection<RestoreTest> RestoreTests { get; set; } = new List<RestoreTest>();
}

/// <summary>
/// سجل النسخ الاحتياطية
/// </summary>
[Table("BackupHistory")]
[Index(nameof(JobId))]
[Index(nameof(BackupDate))]
[Index(nameof(Status))]
public class BackupHistory
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid BackupId { get; set; }
    
    [Required]
    public Guid JobId { get; set; }
    
    [Required]
    [StringLength(255)]
    public string BackupName { get; set; } = string.Empty;
    
    public DateTime BackupDate { get; set; } = DateTime.UtcNow;
    
    public DateTime? StartedAt { get; set; }
    
    public DateTime? CompletedAt { get; set; }
    
    public int DurationMinutes { get; set; } = 0;
    
    public BackupStatus Status { get; set; } = BackupStatus.InProgress;
    
    // Type
    public BackupLevel Level { get; set; } = BackupLevel.Full;
    
    public Guid? ParentBackupId { get; set; } // For incremental/differential
    
    public int GenerationNumber { get; set; } = 1;
    
    // Size and Data
    public long SourceDataSizeBytes { get; set; } = 0;
    
    public long BackupSizeBytes { get; set; } = 0;
    
    public long CompressedSizeBytes { get; set; } = 0;
    
    public double CompressionRatio { get; set; } = 0;
    
    public long DeduplicatedBytes { get; set; } = 0;
    
    public int FilesBackedUp { get; set; } = 0;
    
    public int DatabasesBackedUp { get; set; } = 0;
    
    // Storage
    [Required]
    [StringLength(500)]
    public string StorageLocation { get; set; } = string.Empty;
    
    [StringLength(500)]
    public string? StoragePath { get; set; }
    
    [StringLength(255)]
    public string? StorageContainerId { get; set; }
    
    public bool IsOffsite { get; set; } = false;
    
    public bool IsArchived { get; set; } = false;
    
    public DateTime? ArchivedAt { get; set; }
    
    // Verification
    public bool IsVerified { get; set; } = false;
    
    public DateTime? VerifiedAt { get; set; }
    
    [StringLength(255)]
    public string? Checksum { get; set; }
    
    [StringLength(50)]
    public string? ChecksumAlgorithm { get; set; }
    
    public bool IntegrityValid { get; set; } = true;
    
    // Encryption
    public bool IsEncrypted { get; set; } = true;
    
    [StringLength(50)]
    public string? EncryptionAlgorithm { get; set; }
    
    [StringLength(255)]
    public string? EncryptionKeyId { get; set; }
    
    // Restoration
    public bool IsRestorable { get; set; } = true;
    
    public int RestoreCount { get; set; } = 0;
    
    public DateTime? LastRestoredAt { get; set; }
    
    public bool TestedSuccessfully { get; set; } = false;
    
    public DateTime? LastTestedAt { get; set; }
    
    // Retention
    public DateTime? ExpiresAt { get; set; }
    
    public bool MarkedForDeletion { get; set; } = false;
    
    public DateTime? ScheduledDeletionDate { get; set; }
    
    public RetentionPolicy RetentionPolicy { get; set; } = RetentionPolicy.Standard;
    
    // Performance Metrics
    public double ThroughputMBps { get; set; } = 0;
    
    public int CpuUsagePercent { get; set; } = 0;
    
    public long MemoryUsedBytes { get; set; } = 0;
    
    public long NetworkBytesTransferred { get; set; } = 0;
    
    // Errors and Warnings
    public int ErrorCount { get; set; } = 0;
    
    public string? Errors { get; set; } // JSON array
    
    public int WarningCount { get; set; } = 0;
    
    public string? Warnings { get; set; } // JSON array
    
    [StringLength(500)]
    public string? FailureReason { get; set; }
    
    // Metadata
    [StringLength(100)]
    public string? InitiatedBy { get; set; }
    
    public bool IsManual { get; set; } = false;
    
    public string? BackupMetadata { get; set; } // JSON
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(JobId))]
    public virtual BackupJob Job { get; set; } = null!;
    
    [ForeignKey(nameof(ParentBackupId))]
    public virtual BackupHistory? ParentBackup { get; set; }
    
    public virtual ICollection<BackupHistory> IncrementalBackups { get; set; } = new List<BackupHistory>();
    public virtual ICollection<RestoreOperation> RestoreOperations { get; set; } = new List<RestoreOperation>();
}

/// <summary>
/// اختبارات الاستعادة
/// </summary>
[Table("RestoreTests")]
[Index(nameof(JobId))]
[Index(nameof(TestDate))]
public class RestoreTest
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid TestId { get; set; }
    
    public Guid? JobId { get; set; }
    
    public Guid? BackupId { get; set; }
    
    public DateTime TestDate { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(255)]
    public string TestName { get; set; } = string.Empty;
    
    public TestType Type { get; set; }
    
    public TestStatus Status { get; set; } = TestStatus.Pending;
    
    // Test Configuration
    [Required]
    [StringLength(500)]
    public string TestEnvironment { get; set; } = string.Empty;
    
    public string? TestScenarios { get; set; } // JSON array
    
    public string? TestData { get; set; } // JSON
    
    public bool IsAutomated { get; set; } = false;
    
    // Execution
    public DateTime? StartedAt { get; set; }
    
    public DateTime? CompletedAt { get; set; }
    
    public int DurationMinutes { get; set; } = 0;
    
    [StringLength(100)]
    public string? TestedBy { get; set; }
    
    // Results
    public bool IsSuccessful { get; set; } = false;
    
    public double SuccessRate { get; set; } = 0;
    
    public int TestsPassed { get; set; } = 0;
    
    public int TestsFailed { get; set; } = 0;
    
    public int TestsSkipped { get; set; } = 0;
    
    // Restoration Metrics
    public long DataRestoredBytes { get; set; } = 0;
    
    public int FilesRestored { get; set; } = 0;
    
    public int RestoreTimeMinutes { get; set; } = 0;
    
    public double RestoreThroughputMBps { get; set; } = 0;
    
    // Validation
    public bool DataIntegrityVerified { get; set; } = false;
    
    public bool ApplicationFunctional { get; set; } = false;
    
    public bool PerformanceAcceptable { get; set; } = false;
    
    public string? ValidationResults { get; set; } // JSON
    
    // RTO/RPO Compliance
    public int RTOTargetMinutes { get; set; } = 0;
    
    public int RTOActualMinutes { get; set; } = 0;
    
    public bool RTOCompliant { get; set; } = false;
    
    public int RPOTargetMinutes { get; set; } = 0;
    
    public int RPOActualMinutes { get; set; } = 0;
    
    public bool RPOCompliant { get; set; } = false;
    
    // Issues Found
    public string? IssuesFound { get; set; } // JSON array
    
    public string? Recommendations { get; set; } // JSON array
    
    public string? CorrectiveActions { get; set; } // JSON array
    
    // Report
    [StringLength(500)]
    public string? ReportPath { get; set; }
    
    public DateTime? ReportGeneratedAt { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(JobId))]
    public virtual BackupJob? Job { get; set; }
}

/// <summary>
/// عمليات الاستعادة
/// </summary>
[Table("RestoreOperations")]
[Index(nameof(BackupId))]
[Index(nameof(RestoreDate))]
public class RestoreOperation
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid RestoreId { get; set; }
    
    [Required]
    public Guid BackupId { get; set; }
    
    public DateTime RestoreDate { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(255)]
    public string RestoreReason { get; set; } = string.Empty;
    
    public RestoreType Type { get; set; }
    
    public RestoreStatus Status { get; set; } = RestoreStatus.Pending;
    
    // Target
    [Required]
    [StringLength(500)]
    public string TargetLocation { get; set; } = string.Empty;
    
    [StringLength(255)]
    public string? TargetSystem { get; set; }
    
    [StringLength(255)]
    public string? TargetDatabase { get; set; }
    
    public bool OverwriteExisting { get; set; } = false;
    
    // Selection
    public string? SelectedItems { get; set; } // JSON array
    
    public string? ExcludedItems { get; set; } // JSON array
    
    public bool RestorePermissions { get; set; } = true;
    
    public bool RestoreTimestamps { get; set; } = true;
    
    // Execution
    public DateTime? StartedAt { get; set; }
    
    public DateTime? CompletedAt { get; set; }
    
    public int DurationMinutes { get; set; } = 0;
    
    [Required]
    [StringLength(100)]
    public string RequestedBy { get; set; } = string.Empty;
    
    [StringLength(100)]
    public string? PerformedBy { get; set; }
    
    // Progress
    public double ProgressPercentage { get; set; } = 0;
    
    public long BytesRestored { get; set; } = 0;
    
    public long TotalBytesToRestore { get; set; } = 0;
    
    public int FilesRestored { get; set; } = 0;
    
    public int TotalFilesToRestore { get; set; } = 0;
    
    // Result
    public bool IsSuccessful { get; set; } = false;
    
    public int ErrorCount { get; set; } = 0;
    
    public string? Errors { get; set; } // JSON array
    
    [StringLength(500)]
    public string? FailureReason { get; set; }
    
    // Verification
    public bool DataVerified { get; set; } = false;
    
    public DateTime? VerifiedAt { get; set; }
    
    [StringLength(100)]
    public string? VerifiedBy { get; set; }
    
    // Approval
    public bool RequiresApproval { get; set; } = false;
    
    public bool IsApproved { get; set; } = false;
    
    public DateTime? ApprovedAt { get; set; }
    
    [StringLength(100)]
    public string? ApprovedBy { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public string? Notes { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(BackupId))]
    public virtual BackupHistory Backup { get; set; } = null!;
}

// Enums
public enum BackupType
{
    Database = 1,
    FileSystem = 2,
    Application = 3,
    SystemImage = 4,
    Configuration = 5,
    Virtual = 6,
    Cloud = 7,
    Hybrid = 8
}

public enum BackupScope
{
    Full = 1,
    Partial = 2,
    Selective = 3,
    Critical = 4,
    All = 5
}

public enum JobStatus
{
    Pending = 1,
    Running = 2,
    Paused = 3,
    Completed = 4,
    Failed = 5,
    Cancelled = 6,
    Scheduled = 7
}

public enum CompressionType
{
    None = 0,
    GZip = 1,
    BZip2 = 2,
    LZMA = 3,
    Zstandard = 4,
    LZ4 = 5
}

public enum EncryptionType
{
    None = 0,
    AES128 = 1,
    AES256 = 2,
    RSA = 3,
    ChaCha20 = 4
}

public enum StorageType
{
    Local = 1,
    Network = 2,
    Cloud = 3,
    Tape = 4,
    Hybrid = 5
}

public enum VerificationType
{
    None = 0,
    Checksum = 1,
    Hash = 2,
    BitByBit = 3,
    Restore = 4
}

public enum BackupStatus
{
    Pending = 1,
    InProgress = 2,
    Completed = 3,
    Failed = 4,
    Partial = 5,
    Corrupted = 6,
    Expired = 7
}

public enum BackupLevel
{
    Full = 1,
    Incremental = 2,
    Differential = 3,
    Synthetic = 4,
    Mirror = 5
}

public enum RetentionPolicy
{
    Short = 1,      // 7 days
    Standard = 2,   // 30 days
    Extended = 3,   // 90 days
    Long = 4,       // 365 days
    Archive = 5,    // 7 years
    Permanent = 6   // Forever
}

public enum TestType
{
    Full = 1,
    Partial = 2,
    Random = 3,
    Critical = 4,
    Compliance = 5
}

public enum TestStatus
{
    Pending = 1,
    Running = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5
}

public enum RestoreType
{
    Full = 1,
    Selective = 2,
    PointInTime = 3,
    Granular = 4,
    Disaster = 5
}

public enum RestoreStatus
{
    Pending = 1,
    InProgress = 2,
    Completed = 3,
    Failed = 4,
    Partial = 5,
    Cancelled = 6
}}
</artifact>
</artifacts>*/

using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SabaFone.Backend.Data.Backups.Models
{
    public class BackupJob
    {
        [Key]
        public Guid JobId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(100)]
        public string JobName { get; set; }

        [MaxLength(500)]
        public string Description { get; set; }

        [Required]
        [MaxLength(50)]
        public string BackupType { get; set; } // Full, Incremental, Differential

        [MaxLength(500)]
        public string SourcePath { get; set; }

        [MaxLength(500)]
        public string DestinationPath { get; set; }

        [MaxLength(100)]
        public string Schedule { get; set; } // Cron expression

        public int RetentionDays { get; set; } = 30;

        public bool IsScheduled { get; set; } = false;
        public bool IsActive { get; set; } = true;
        public bool CompressionEnabled { get; set; } = true;
        public bool EncryptionEnabled { get; set; } = true;

        [MaxLength(20)]
        public string Status { get; set; } // Idle, Running, Completed, Failed

        public DateTime? LastRunTime { get; set; }
        public DateTime? NextRunTime { get; set; }

        [MaxLength(20)]
        public string LastRunStatus { get; set; } // Success, Failed, Warning

        public string LastRunMessage { get; set; }

        [Column(TypeName = "bigint")]
        public long? BackupSize { get; set; } // Bytes

        [Column(TypeName = "decimal(10,2)")]
        public decimal? Duration { get; set; } // Minutes

        public string BackupMetadata { get; set; } // JSON
        public string BackupHistory { get; set; } // JSON array

        public int TotalRuns { get; set; } = 0;
        public int SuccessfulRuns { get; set; } = 0;
        public int FailedRuns { get; set; } = 0;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        
        public Guid? CreatedBy { get; set; }
        public Guid? UpdatedBy { get; set; }

        // Navigation properties
        public virtual Users.Models.User CreatedByUser { get; set; }
    }
}