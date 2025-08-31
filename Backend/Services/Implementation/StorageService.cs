using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace SabaFone.Backend.Services.Implementation
{
    public class StorageService : IStorageService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<StorageService> _logger;
        private readonly string _basePath;
        private readonly string _backupPath;
        private readonly string _tempPath;

        public StorageService(IConfiguration configuration, ILogger<StorageService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            
            _basePath = _configuration["Storage:LocalPath"] ?? "C:\\SabaFone\\Storage";
            _backupPath = _configuration["Storage:BackupPath"] ?? "C:\\SabaFone\\Backups";
            _tempPath = _configuration["Storage:TempPath"] ?? Path.GetTempPath();
            
            // Ensure directories exist
            Directory.CreateDirectory(_basePath);
            Directory.CreateDirectory(_backupPath);
            Directory.CreateDirectory(_tempPath);
        }

        public async Task<string> SaveFileAsync(Stream fileStream, string fileName, string folder = null)
        {
            try
            {
                var targetPath = string.IsNullOrEmpty(folder) 
                    ? _basePath 
                    : Path.Combine(_basePath, folder);
                
                Directory.CreateDirectory(targetPath);
                
                var filePath = Path.Combine(targetPath, fileName);
                
                using (var fileOutputStream = new FileStream(filePath, FileMode.Create))
                {
                    await fileStream.CopyToAsync(fileOutputStream);
                }
                
                _logger.LogInformation($"File saved: {filePath}");
                return filePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving file {fileName}");
                throw;
            }
        }

        public async Task<Stream> GetFileAsync(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"File not found: {filePath}");
                }
                
                var memoryStream = new MemoryStream();
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    await fileStream.CopyToAsync(memoryStream);
                }
                
                memoryStream.Position = 0;
                return memoryStream;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error reading file {filePath}");
                throw;
            }
        }

        public async Task<bool> DeleteFileAsync(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    await Task.Run(() => File.Delete(filePath));
                    _logger.LogInformation($"File deleted: {filePath}");
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting file {filePath}");
                return false;
            }
        }

        public async Task<bool> FileExistsAsync(string filePath)
        {
            return await Task.FromResult(File.Exists(filePath));
        }

        public async Task<long> GetFileSizeAsync(string filePath)
        {
            if (!File.Exists(filePath))
                return 0;
            
            var fileInfo = new FileInfo(filePath);
            return await Task.FromResult(fileInfo.Length);
        }

        public async Task<bool> CreateDirectoryAsync(string path)
        {
            try
            {
                await Task.Run(() => Directory.CreateDirectory(path));
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating directory {path}");
                return false;
            }
        }

        public async Task<bool> DeleteDirectoryAsync(string path, bool recursive = false)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    await Task.Run(() => Directory.Delete(path, recursive));
                    return true;
                }
                
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting directory {path}");
                return false;
            }
        }

        public async Task<List<string>> GetFilesAsync(string directory, string searchPattern = "*")
        {
            try
            {
                if (!Directory.Exists(directory))
                    return new List<string>();
                
                var files = await Task.Run(() => 
                    Directory.GetFiles(directory, searchPattern, SearchOption.TopDirectoryOnly).ToList());
                
                return files;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting files from {directory}");
                return new List<string>();
            }
        }

        public async Task<List<string>> GetDirectoriesAsync(string directory)
        {
            try
            {
                if (!Directory.Exists(directory))
                    return new List<string>();
                
                var directories = await Task.Run(() => 
                    Directory.GetDirectories(directory).ToList());
                
                return directories;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting directories from {directory}");
                return new List<string>();
            }
        }

        public async Task<long> GetAvailableSpaceAsync(string drive = null)
        {
            try
            {
                var drivePath = drive ?? Path.GetPathRoot(_basePath);
                var driveInfo = new DriveInfo(drivePath);
                
                return await Task.FromResult(driveInfo.AvailableFreeSpace);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting available space for {drive}");
                return 0;
            }
        }

        public async Task<long> GetUsedSpaceAsync(string path = null)
        {
            try
            {
                var targetPath = path ?? _basePath;
                
                if (!Directory.Exists(targetPath))
                    return 0;
                
                var directoryInfo = new DirectoryInfo(targetPath);
                var totalSize = await Task.Run(() => 
                    directoryInfo.GetFiles("*", SearchOption.AllDirectories).Sum(file => file.Length));
                
                return totalSize;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error calculating used space for {path}");
                return 0;
            }
        }

        public async Task<bool> CleanupTempFilesAsync()
        {
            try
            {
                var tempFiles = Directory.GetFiles(_tempPath);
                var deletedCount = 0;
                
                foreach (var file in tempFiles)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastAccessTime < DateTime.Now.AddDays(-1))
                        {
                            await DeleteFileAsync(file);
                            deletedCount++;
                        }
                    }
                    catch
                    {
                        // Skip files that can't be deleted
                    }
                }
                
                _logger.LogInformation($"Cleaned up {deletedCount} temp files");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error cleaning up temp files");
                return false;
            }
        }

        public async Task<Dictionary<string, long>> GetStorageStatisticsAsync()
        {
            var stats = new Dictionary<string, long>();
            
            try
            {
                var driveInfo = new DriveInfo(Path.GetPathRoot(_basePath));
                
                stats["TotalSpace"] = driveInfo.TotalSize;
                stats["AvailableSpace"] = driveInfo.AvailableFreeSpace;
                stats["UsedSpace"] = driveInfo.TotalSize - driveInfo.AvailableFreeSpace;
                stats["BackupStorageUsed"] = await GetUsedSpaceAsync(_backupPath);
                stats["TempStorageUsed"] = await GetUsedSpaceAsync(_tempPath);
                stats["FileCount"] = Directory.GetFiles(_basePath, "*", SearchOption.AllDirectories).Length;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting storage statistics");
            }
            
            return stats;
        }

        public async Task<string> SaveBackupAsync(byte[] backupData, string backupName)
        {
            try
            {
                var backupFilePath = Path.Combine(_backupPath, $"{backupName}_{DateTime.UtcNow:yyyyMMddHHmmss}.bak");
                
                await File.WriteAllBytesAsync(backupFilePath, backupData);
                
                _logger.LogInformation($"Backup saved: {backupFilePath}");
                return backupFilePath;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error saving backup {backupName}");
                throw;
            }
        }

        public async Task<byte[]> GetBackupAsync(string backupPath)
        {
            try
            {
                if (!File.Exists(backupPath))
                {
                    throw new FileNotFoundException($"Backup not found: {backupPath}");
                }
                
                return await File.ReadAllBytesAsync(backupPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error reading backup {backupPath}");
                throw;
            }
        }

        public async Task<bool> MoveBackupToArchiveAsync(string backupPath)
        {
            try
            {
                var archivePath = Path.Combine(_backupPath, "Archive");
                Directory.CreateDirectory(archivePath);
                
                var fileName = Path.GetFileName(backupPath);
                var destinationPath = Path.Combine(archivePath, fileName);
                
                await Task.Run(() => File.Move(backupPath, destinationPath));
                
                _logger.LogInformation($"Backup moved to archive: {destinationPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error moving backup to archive: {backupPath}");
                return false;
            }
        }

        public async Task<bool> UploadToCloudAsync(string localPath, string cloudPath)
        {
            try
            {
                // In production, integrate with cloud storage (Azure Blob, AWS S3, etc.)
                _logger.LogInformation($"Upload to cloud: {localPath} -> {cloudPath}");
                
                // Simulate upload
                await Task.Delay(2000);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error uploading to cloud: {localPath}");
                return false;
            }
        }

        public async Task<bool> DownloadFromCloudAsync(string cloudPath, string localPath)
        {
            try
            {
                // In production, integrate with cloud storage
                _logger.LogInformation($"Download from cloud: {cloudPath} -> {localPath}");
                
                // Simulate download
                await Task.Delay(2000);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error downloading from cloud: {cloudPath}");
                return false;
            }
        }

        public async Task<bool> DeleteFromCloudAsync(string cloudPath)
        {
            try
            {
                // In production, integrate with cloud storage
                _logger.LogInformation($"Delete from cloud: {cloudPath}");
                
                await Task.Delay(500);
                
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting from cloud: {cloudPath}");
                return false;
            }
        }

        public async Task<List<object>> ListCloudFilesAsync(string prefix = null)
        {
            // In production, list files from cloud storage
            var files = new List<object>
            {
                new { Name = "backup_20240101.bak", Size = 1073741824L, Modified = DateTime.UtcNow.AddDays(-5) },
                new { Name = "backup_20240102.bak", Size = 2147483648L, Modified = DateTime.UtcNow.AddDays(-3) }
            };
            
            return await Task.FromResult(files);
        }

        public async Task<byte[]> CompressDataAsync(byte[] data)
        {
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(output, CompressionMode.Compress))
                {
                    await gzip.WriteAsync(data, 0, data.Length);
                }
                
                return output.ToArray();
            }
        }

        public async Task<byte[]> DecompressDataAsync(byte[] compressedData)
        {
            using (var input = new MemoryStream(compressedData))
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(input, CompressionMode.Decompress))
                {
                    await gzip.CopyToAsync(output);
                }
                
                return output.ToArray();
            }
        }

        public async Task<bool> CompressFileAsync(string inputPath, string outputPath)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(inputPath);
                var compressedData = await CompressDataAsync(data);
                await File.WriteAllBytesAsync(outputPath, compressedData);
                
                _logger.LogInformation($"File compressed: {inputPath} -> {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error compressing file {inputPath}");
                return false;
            }
        }

        public async Task<bool> DecompressFileAsync(string inputPath, string outputPath)
        {
            try
            {
                var compressedData = await File.ReadAllBytesAsync(inputPath);
                var data = await DecompressDataAsync(compressedData);
                await File.WriteAllBytesAsync(outputPath, data);
                
                _logger.LogInformation($"File decompressed: {inputPath} -> {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error decompressing file {inputPath}");
                return false;
            }
        }
    }
}