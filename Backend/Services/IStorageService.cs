using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace SabaFone.Backend.Services
{
    public interface IStorageService
    {
        // File Operations
        Task<string> SaveFileAsync(Stream fileStream, string fileName, string folder = null);
        Task<Stream> GetFileAsync(string filePath);
        Task<bool> DeleteFileAsync(string filePath);
        Task<bool> FileExistsAsync(string filePath);
        Task<long> GetFileSizeAsync(string filePath);
        
        // Directory Operations
        Task<bool> CreateDirectoryAsync(string path);
        Task<bool> DeleteDirectoryAsync(string path, bool recursive = false);
        Task<List<string>> GetFilesAsync(string directory, string searchPattern = "*");
        Task<List<string>> GetDirectoriesAsync(string directory);
        
        // Storage Management
        Task<long> GetAvailableSpaceAsync(string drive = null);
        Task<long> GetUsedSpaceAsync(string path = null);
        Task<bool> CleanupTempFilesAsync();
        Task<Dictionary<string, long>> GetStorageStatisticsAsync();
        
        // Backup Storage
        Task<string> SaveBackupAsync(byte[] backupData, string backupName);
        Task<byte[]> GetBackupAsync(string backupPath);
        Task<bool> MoveBackupToArchiveAsync(string backupPath);
        
        // Cloud Storage (if configured)
        Task<bool> UploadToCloudAsync(string localPath, string cloudPath);
        Task<bool> DownloadFromCloudAsync(string cloudPath, string localPath);
        Task<bool> DeleteFromCloudAsync(string cloudPath);
        Task<List<object>> ListCloudFilesAsync(string prefix = null);
        
        // Compression
        Task<byte[]> CompressDataAsync(byte[] data);
        Task<byte[]> DecompressDataAsync(byte[] compressedData);
        Task<bool> CompressFileAsync(string inputPath, string outputPath);
        Task<bool> DecompressFileAsync(string inputPath, string outputPath);
    }
}