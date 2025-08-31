using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Encryption.Models;
using SabaFone.Backend.Exceptions;

namespace SabaFone.Backend.Services.Implementation
{
    public class KeyManagementService : IKeyManagementService
    {
        private readonly SsasDbContext _context;
        private readonly ILogger<KeyManagementService> _logger;
        private readonly IAuditService _auditService;

        public KeyManagementService(
            SsasDbContext context,
            ILogger<KeyManagementService> logger,
            IAuditService auditService)
        {
            _context = context;
            _logger = logger;
            _auditService = auditService;
        }

        public async Task<EncryptionKey> CreateKeyAsync(string keyName, string keyType, int keySize)
        {
            try
            {
                // Generate key material
                var keyMaterial = GenerateKeyMaterial(keySize);
                
                var encryptionKey = new EncryptionKey
                {
                    KeyId = Guid.NewGuid(),
                    KeyName = keyName,
                    KeyType = keyType,
                    KeySize = keySize,
                    KeyValue = Convert.ToBase64String(keyMaterial),
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddYears(1),
                    IsActive = true,
                    Status = "Active",
                    Version = 1,
                    Algorithm = keyType == "Symmetric" ? "AES" : "RSA"
                };

                _context.EncryptionKeys.Add(encryptionKey);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_CREATED", $"Encryption key created: {keyName}");

                return encryptionKey;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error creating key {keyName}");
                throw;
            }
        }

        public async Task<EncryptionKey> GetKeyAsync(string keyId)
        {
            if (Guid.TryParse(keyId, out var guid))
            {
                return await _context.EncryptionKeys
                    .FirstOrDefaultAsync(k => k.KeyId == guid && k.IsActive);
            }
            
            return await _context.EncryptionKeys
                .FirstOrDefaultAsync(k => k.KeyName == keyId && k.IsActive);
        }

        public async Task<List<EncryptionKey>> GetActiveKeysAsync()
        {
            return await _context.EncryptionKeys
                .Where(k => k.IsActive && k.Status == "Active")
                .OrderByDescending(k => k.CreatedAt)
                .ToListAsync();
        }

        public async Task<bool> RotateKeyAsync(string keyId)
        {
            try
            {
                var oldKey = await GetKeyAsync(keyId);
                if (oldKey == null) return false;

                // Create new version of the key
                var newKeyMaterial = GenerateKeyMaterial(oldKey.KeySize);
                
                var newKey = new EncryptionKey
                {
                    KeyId = Guid.NewGuid(),
                    KeyName = oldKey.KeyName,
                    KeyType = oldKey.KeyType,
                    KeySize = oldKey.KeySize,
                    KeyValue = Convert.ToBase64String(newKeyMaterial),
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddYears(1),
                    IsActive = true,
                    Status = "Active",
                    Version = oldKey.Version + 1,
                    Algorithm = oldKey.Algorithm,
                    PreviousKeyId = oldKey.KeyId
                };

                // Deactivate old key
                oldKey.IsActive = false;
                oldKey.Status = "Rotated";
                oldKey.RotatedAt = DateTime.UtcNow;

                _context.EncryptionKeys.Add(newKey);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_ROTATED", $"Key rotated: {oldKey.KeyName}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error rotating key {keyId}");
                return false;
            }
        }

        public async Task<bool> RevokeKeyAsync(string keyId, string reason)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                if (key == null) return false;

                key.IsActive = false;
                key.Status = "Revoked";
                key.RevokedAt = DateTime.UtcNow;
                key.RevokedReason = reason;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_REVOKED", $"Key revoked: {key.KeyName}, Reason: {reason}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error revoking key {keyId}");
                return false;
            }
        }

        public async Task<bool> DeleteKeyAsync(string keyId)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                if (key == null) return false;

                // Soft delete
                key.IsActive = false;
                key.Status = "Deleted";
                key.DeletedAt = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_DELETED", $"Key deleted: {key.KeyName}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting key {keyId}");
                return false;
            }
        }

        public async Task<bool> StoreKeyAsync(string keyId, byte[] keyData, bool isSecure = true)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                if (key == null) return false;

                if (isSecure)
                {
                    // Encrypt key data before storing
                    keyData = ProtectKeyData(keyData);
                }

                key.KeyValue = Convert.ToBase64String(keyData);
                key.LastModified = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error storing key {keyId}");
                return false;
            }
        }

        public async Task<byte[]> RetrieveKeyAsync(string keyId)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                if (key == null) return null;

                var keyData = Convert.FromBase64String(key.KeyValue);

                // Update usage count
                key.UsageCount++;
                key.LastUsed = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                return keyData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error retrieving key {keyId}");
                return null;
            }
        }

        public async Task<bool> BackupKeyAsync(string keyId, string backupLocation)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                if (key == null) return false;

                // Create backup
                var backup = new
                {
                    KeyId = key.KeyId,
                    KeyName = key.KeyName,
                    KeyType = key.KeyType,
                    KeyValue = key.KeyValue,
                    BackupDate = DateTime.UtcNow,
                    BackupLocation = backupLocation
                };

                // Save backup (simplified - in production, save to secure storage)
                var backupJson = System.Text.Json.JsonSerializer.Serialize(backup);
                var backupPath = System.IO.Path.Combine(backupLocation, $"key_backup_{key.KeyId}_{DateTime.UtcNow:yyyyMMddHHmmss}.json");
                await System.IO.File.WriteAllTextAsync(backupPath, backupJson);

                key.LastBackup = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_BACKED_UP", $"Key backed up: {key.KeyName}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error backing up key {keyId}");
                return false;
            }
        }

        public async Task<bool> RestoreKeyAsync(string keyId, string backupLocation)
        {
            try
            {
                var backupPath = System.IO.Path.Combine(backupLocation, $"key_backup_{keyId}_*.json");
                var files = System.IO.Directory.GetFiles(backupLocation, $"key_backup_{keyId}_*.json");
                
                if (files.Length == 0) return false;

                // Get most recent backup
                var mostRecent = files.OrderByDescending(f => System.IO.File.GetCreationTime(f)).First();
                var backupJson = await System.IO.File.ReadAllTextAsync(mostRecent);
                var backup = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(backupJson);

                // Restore key
                var key = await GetKeyAsync(keyId);
                if (key == null)
                {
                    // Create new key from backup
                    key = new EncryptionKey
                    {
                        KeyId = Guid.Parse(backup["KeyId"].ToString()),
                        KeyName = backup["KeyName"].ToString(),
                        KeyType = backup["KeyType"].ToString(),
                        KeyValue = backup["KeyValue"].ToString(),
                        CreatedAt = DateTime.UtcNow,
                        IsActive = true,
                        Status = "Restored"
                    };
                    
                    _context.EncryptionKeys.Add(key);
                }
                else
                {
                    key.KeyValue = backup["KeyValue"].ToString();
                    key.Status = "Restored";
                }

                await _context.SaveChangesAsync();

                await _auditService.LogAsync("KEY_RESTORED", $"Key restored: {key.KeyName}");

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error restoring key {keyId}");
                return false;
            }
        }

        public async Task<bool> ValidateKeyUsageAsync(string keyId, string purpose)
        {
            var key = await GetKeyAsync(keyId);
            if (key == null) return false;

            // Check if key is active
            if (!key.IsActive || key.Status != "Active")
                return false;

            // Check expiration
            if (key.ExpiresAt < DateTime.UtcNow)
                return false;

            // Check purpose (simplified)
            if (!string.IsNullOrEmpty(key.Purpose) && key.Purpose != purpose)
                return false;

            return true;
        }

        public async Task<bool> UpdateKeyUsageAsync(string keyId, int usageCount)
        {
            var key = await GetKeyAsync(keyId);
            if (key == null) return false;

            key.UsageCount += usageCount;
            key.LastUsed = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return true;
        }

        public async Task<Dictionary<string, object>> GetKeyStatisticsAsync(string keyId)
        {
            var key = await GetKeyAsync(keyId);
            if (key == null) return null;

            var stats = new Dictionary<string, object>
            {
                ["KeyId"] = key.KeyId,
                ["KeyName"] = key.KeyName,
                ["UsageCount"] = key.UsageCount,
                ["CreatedAt"] = key.CreatedAt,
                ["ExpiresAt"] = key.ExpiresAt,
                ["LastUsed"] = key.LastUsed,
                ["DaysUntilExpiry"] = (key.ExpiresAt - DateTime.UtcNow).Days,
                ["IsActive"] = key.IsActive,
                ["Status"] = key.Status
            };

            return stats;
        }

        public async Task<bool> EncryptKeyAsync(string keyId, string masterKeyId)
        {
            try
            {
                var key = await GetKeyAsync(keyId);
                var masterKey = await GetKeyAsync(masterKeyId);
                
                if (key == null || masterKey == null) return false;

                var keyData = Convert.FromBase64String(key.KeyValue);
                var encryptedData = EncryptWithMasterKey(keyData, Convert.FromBase64String(masterKey.KeyValue));
                
                key.KeyValue = Convert.ToBase64String(encryptedData);
                key.IsEncrypted = true;
                key.EncryptedWith = masterKeyId;

                await _context.SaveChangesAsync();

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error encrypting key {keyId}");
                return false;
            }
        }

        public async Task<bool> SetKeyExpirationAsync(string keyId, DateTime expirationDate)
        {
            var key = await GetKeyAsync(keyId);
            if (key == null) return false;

            key.ExpiresAt = expirationDate;
            await _context.SaveChangesAsync();

            await _auditService.LogAsync("KEY_EXPIRATION_SET", $"Key expiration set: {key.KeyName}, Expires: {expirationDate}");

            return true;
        }

        public async Task<List<EncryptionKey>> GetExpiringKeysAsync(int daysThreshold)
        {
            var thresholdDate = DateTime.UtcNow.AddDays(daysThreshold);
            
            return await _context.EncryptionKeys
                .Where(k => k.IsActive && k.ExpiresAt <= thresholdDate)
                .OrderBy(k => k.ExpiresAt)
                .ToListAsync();
        }

        public async Task<bool> AuditKeyUsageAsync(string keyId, string operation, Guid userId)
        {
            await _auditService.LogAsync($"KEY_USAGE_{operation}", $"Key {keyId} used for {operation}", userId);
            return true;
        }

        private byte[] GenerateKeyMaterial(int keySize)
        {
            var key = new byte[keySize / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        private byte[] ProtectKeyData(byte[] keyData)
        {
            // Use DPAPI or similar for protecting key data
            // Simplified for demo
            return keyData;
        }

        private byte[] EncryptWithMasterKey(byte[] data, byte[] masterKey)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = masterKey.Take(32).ToArray(); // Use first 32 bytes for AES-256
                aes.GenerateIV();
                
                using (var encryptor = aes.CreateEncryptor())
                {
                    var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
                    
                    // Prepend IV to encrypted data
                    var result = new byte[aes.IV.Length + encrypted.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
                    
                    return result;
                }
            }
        }
    }
}