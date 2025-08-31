//1️⃣ Data/Security/Models/SecurityEvent.cs

/*<artifacts>
<artifact identifier="security-event-model" type="application/vnd.ant.code" language="csharp" title="Data/Security/Models/SecurityEvent.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Data/Security/Models/SecurityEvent.cs
// نموذج الأحداث الأمنية - شركة سبأفون
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
namespace SabaFone.Backend.Data.Security.Models
{
/// <summary>
/// الأحداث الأمنية
/// </summary>
[Table("SecurityEvents")]
[Index(nameof(EventTime))]
[Index(nameof(EventType))]
[Index(nameof(Severity))]
[Index(nameof(Status))]
public class SecurityEvent
{
[Key]
[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
public Guid EventId { get; set; }
[Required]
    [StringLength(100)]
    public string EventType { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string Title { get; set; } = string.Empty;
    
    [Required]
    public string Description { get; set; } = string.Empty;
    
    public DateTime EventTime { get; set; } = DateTime.UtcNow;
    
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? ResolvedAt { get; set; }
    
    // Severity and Priority
    public EventSeverity Severity { get; set; }
    
    public EventPriority Priority { get; set; }
    
    public int RiskScore { get; set; } = 0;
    
    public EventStatus Status { get; set; } = EventStatus.New;
    
    // Source Information
    [StringLength(50)]
    public string? SourceIp { get; set; }
    
    [StringLength(255)]
    public string? SourceHost { get; set; }
    
    [StringLength(10)]
    public string? SourcePort { get; set; }
    
    [StringLength(100)]
    public string? SourceCountry { get; set; }
    
    [StringLength(100)]
    public string? SourceCity { get; set; }
    
    [StringLength(500)]
    public string? SourceUserAgent { get; set; }
    
    // Target Information
    [StringLength(50)]
    public string? TargetIp { get; set; }
    
    [StringLength(255)]
    public string? TargetHost { get; set; }
    
    [StringLength(10)]
    public string? TargetPort { get; set; }
    
    [StringLength(255)]
    public string? TargetResource { get; set; }
    
    [StringLength(100)]
    public string? TargetService { get; set; }
    
    // User Information
    public Guid? UserId { get; set; }
    
    [StringLength(100)]
    public string? Username { get; set; }
    
    [StringLength(255)]
    public string? UserEmail { get; set; }
    
    [StringLength(100)]
    public string? UserRole { get; set; }
    
    // Detection Information
    [StringLength(100)]
    public string? DetectionMethod { get; set; }
    
    [StringLength(100)]
    public string? DetectionSource { get; set; }
    
    [StringLength(100)]
    public string? DetectionRule { get; set; }
    
    public double? DetectionConfidence { get; set; }
    
    // Attack Information
    [StringLength(100)]
    public string? AttackType { get; set; }
    
    [StringLength(100)]
    public string? AttackVector { get; set; }
    
    [StringLength(100)]
    public string? AttackPattern { get; set; }
    
    public string? AttackPayload { get; set; } // JSON
    
    // Impact Assessment
    public ImpactLevel ImpactLevel { get; set; } = ImpactLevel.Low;
    
    public string? ImpactDescription { get; set; }
    
    public int? AffectedUsers { get; set; }
    
    public int? AffectedSystems { get; set; }
    
    public decimal? EstimatedDamage { get; set; }
    
    // Response Information
    public string? ResponseActions { get; set; } // JSON array
    
    public DateTime? ResponseStartedAt { get; set; }
    
    public DateTime? ResponseCompletedAt { get; set; }
    
    [StringLength(100)]
    public string? RespondedBy { get; set; }
    
    public bool AutoResponse { get; set; } = false;
    
    public bool ManualIntervention { get; set; } = false;
    
    // Investigation
    public Guid? AssignedTo { get; set; }
    
    [StringLength(100)]
    public string? AssignedToName { get; set; }
    
    public DateTime? AssignedAt { get; set; }
    
    public InvestigationStatus InvestigationStatus { get; set; } = InvestigationStatus.NotStarted;
    
    public string? InvestigationNotes { get; set; }
    
    public string? RootCause { get; set; }
    
    // Indicators of Compromise (IoCs)
    public string? IoCs { get; set; } // JSON array
    
    public string? RelatedIoCs { get; set; } // JSON array
    
    // Evidence
    public string? Evidence { get; set; } // JSON array of file paths/references
    
    public string? LogEntries { get; set; } // JSON array
    
    public string? Screenshots { get; set; } // JSON array of URLs
    
    // Correlation
    public Guid? ParentEventId { get; set; }
    
    public string? CorrelationId { get; set; }
    
    public int RelatedEventsCount { get; set; } = 0;
    
    public bool IsCorrelated { get; set; } = false;
    
    // Threat Intelligence
    public string? ThreatIntelSource { get; set; }
    
    public string? ThreatActorName { get; set; }
    
    public string? ThreatActorGroup { get; set; }
    
    public string? MitreTactics { get; set; } // JSON array
    
    public string? MitreTechniques { get; set; } // JSON array
    
    public string? CveReferences { get; set; } // JSON array
    
    // Compliance
    public string? ComplianceViolations { get; set; } // JSON array
    
    public string? RegulatoryRequirements { get; set; } // JSON array
    
    public bool ReportRequired { get; set; } = false;
    
    public DateTime? ReportedAt { get; set; }
    
    // Metadata
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [StringLength(100)]
    public string? CreatedBy { get; set; }
    
    public DateTime? UpdatedAt { get; set; }
    
    [StringLength(100)]
    public string? UpdatedBy { get; set; }
    
    public bool IsDeleted { get; set; } = false;
    
    public DateTime? DeletedAt { get; set; }
    
    // Additional Data
    public string? AdditionalData { get; set; } // JSON
    
    public string? Tags { get; set; } // JSON array
    
    public string? CustomFields { get; set; } // JSON
    
    // Navigation Properties
    public virtual ICollection<SecurityEventComment> Comments { get; set; } = new List<SecurityEventComment>();
    public virtual ICollection<SecurityEventAttachment> Attachments { get; set; } = new List<SecurityEventAttachment>();
    public virtual ICollection<SecurityEventAction> Actions { get; set; } = new List<SecurityEventAction>();
    public virtual ICollection<ThreatIndicator> ThreatIndicators { get; set; } = new List<ThreatIndicator>();
    
    [ForeignKey(nameof(ParentEventId))]
    public virtual SecurityEvent? ParentEvent { get; set; }
    
    public virtual ICollection<SecurityEvent> ChildEvents { get; set; } = new List<SecurityEvent>();
}

/// <summary>
/// تعليقات الأحداث الأمنية
/// </summary>
[Table("SecurityEventComments")]
[Index(nameof(EventId))]
public class SecurityEventComment
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid CommentId { get; set; }
    
    [Required]
    public Guid EventId { get; set; }
    
    [Required]
    public string Comment { get; set; } = string.Empty;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(100)]
    public string CreatedBy { get; set; } = string.Empty;
    
    public Guid? CreatedByUserId { get; set; }
    
    public bool IsInternal { get; set; } = false;
    
    public bool IsEdited { get; set; } = false;
    
    public DateTime? EditedAt { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(EventId))]
    public virtual SecurityEvent Event { get; set; } = null!;
}

/// <summary>
/// مرفقات الأحداث الأمنية
/// </summary>
[Table("SecurityEventAttachments")]
[Index(nameof(EventId))]
public class SecurityEventAttachment
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid AttachmentId { get; set; }
    
    [Required]
    public Guid EventId { get; set; }
    
    [Required]
    [StringLength(255)]
    public string FileName { get; set; } = string.Empty;
    
    [Required]
    [StringLength(500)]
    public string FilePath { get; set; } = string.Empty;
    
    [StringLength(100)]
    public string? FileType { get; set; }
    
    public long FileSize { get; set; }
    
    [StringLength(255)]
    public string? FileHash { get; set; }
    
    [StringLength(500)]
    public string? Description { get; set; }
    
    public DateTime UploadedAt { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(100)]
    public string UploadedBy { get; set; } = string.Empty;
    
    public bool IsEvidence { get; set; } = false;
    
    public bool IsQuarantined { get; set; } = false;
    
    // Navigation Properties
    [ForeignKey(nameof(EventId))]
    public virtual SecurityEvent Event { get; set; } = null!;
}

/// <summary>
/// إجراءات الأحداث الأمنية
/// </summary>
[Table("SecurityEventActions")]
[Index(nameof(EventId))]
public class SecurityEventAction
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public Guid ActionId { get; set; }
    
    [Required]
    public Guid EventId { get; set; }
    
    [Required]
    [StringLength(100)]
    public string ActionType { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string ActionDescription { get; set; } = string.Empty;
    
    public DateTime ActionTime { get; set; } = DateTime.UtcNow;
    
    [Required]
    [StringLength(100)]
    public string PerformedBy { get; set; } = string.Empty;
    
    public Guid? PerformedByUserId { get; set; }
    
    public bool IsAutomated { get; set; } = false;
    
    public bool IsSuccessful { get; set; } = true;
    
    [StringLength(500)]
    public string? ErrorMessage { get; set; }
    
    public string? ActionDetails { get; set; } // JSON
    
    public string? ActionResult { get; set; } // JSON
    
    public int? DurationMs { get; set; }
    
    // Navigation Properties
    [ForeignKey(nameof(EventId))]
    public virtual SecurityEvent Event { get; set; } = null!;
}

// Enums
public enum EventSeverity
{
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

public enum EventPriority
{
    Low = 1,
    Normal = 2,
    High = 3,
    Urgent = 4,
    Critical = 5
}

public enum EventStatus
{
    New = 1,
    InProgress = 2,
    Investigating = 3,
    Resolved = 4,
    Closed = 5,
    FalsePositive = 6,
    Escalated = 7,
    Suppressed = 8
}

public enum ImpactLevel
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
    Catastrophic = 5
}

public enum InvestigationStatus
{
    NotStarted = 0,
    InProgress = 1,
    Pending = 2,
    Completed = 3,
    Cancelled = 4,
    Escalated = 5
}}
</artifact>
</artifacts>*/
using System;
using System.ComponentModel.DataAnnotations;

namespace SabaFone.Backend.Data.Security.Models
{
    public class SecurityEvent
    {
        [Key]
        public Guid EventId { get; set; } = Guid.NewGuid();

        [Required]
        [MaxLength(50)]
        public string EventType { get; set; }

        [Required]
        [MaxLength(20)]
        public string Severity { get; set; } // Critical, High, Medium, Low

        [MaxLength(1000)]
        public string Description { get; set; }

        [MaxLength(100)]
        public string Source { get; set; }

        [MaxLength(45)]
        public string SourceIp { get; set; }

        public string TargetResource { get; set; }
        public string TargetUser { get; set; }
        
        public string EventData { get; set; } // JSON data

        public DateTime EventTime { get; set; } = DateTime.UtcNow;
        
        public bool IsResolved { get; set; } = false;
        public DateTime? ResolvedAt { get; set; }
        public string ResolutionNotes { get; set; }
        public Guid? ResolvedBy { get; set; }

        public Guid? UserId { get; set; }

        // Navigation properties
        public virtual Users.Models.User User { get; set; }
    }
}