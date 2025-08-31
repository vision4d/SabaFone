using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Backups.Models;

namespace SabaFone.Backend.Services
{
    public interface IBackupService
    {
        // Backup Operations
        Task<Guid> StartBackupAsync(BackupJob job);
        Task<bool> StopBackupAsync(Guid backupId);
        Task<object> GetBackupStatusAsync(Guid backupId);
        Task ExecuteBackupAsync(Guid backupId);
        
        // Restore Operations
        Task<Guid> StartRestoreAsync(Guid backupId, Dictionary<string, object> options);
        Task<bool> ValidateBackupIntegrityAsync(Guid backupId);
        Task ExecuteRestoreAsync(Guid restoreId);
        Task<object> GetRestoreStatusAsync(Guid restoreId);
        
        // Backup Jobs
        Task<BackupJob> CreateBackupJobAsync(BackupJob job);
        Task<bool> UpdateBackupJobAsync(Guid jobId, Dictionary<string, object> updates);
        Task<bool> DeleteBackupJobAsync(Guid jobId);
        Task<List<BackupJob>> GetBackupJobsAsync(bool activeOnly = true);
        Task<bool> ScheduleJobAsync(Guid jobId);
        
        // Backup Management
        Task<bool> RotateBackupsAsync(Guid jobId);
        Task<bool> CleanupOldBackupsAsync(int retentionDays);
        Task<long> CalculateBackupSizeAsync(BackupJob job);
        Task<DateTime?> CalculateNextRunTime(string schedule);
        
        // Testing
        Task ExecuteRestoreTestAsync(Guid testId);
        Task<bool> VerifyBackupAsync(Guid backupId);
        Task<object> TestRestoreAsync(Guid backupId, string testEnvironment);
        
        // Reporting
        Task<Dictionary<string, object>> GetBackupStatisticsAsync();
        Task<byte[]> GenerateBackupReportAsync(DateTime startDate, DateTime endDate);
        Task<List<object>> GetBackupHistoryAsync(Guid? jobId = null);
    }
}