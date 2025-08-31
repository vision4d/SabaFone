using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SabaFone.Backend.Data.Encryption.Models;

namespace SabaFone.Backend.Services
{
    public interface IKeyManagementService
    {
        // Key Lifecycle
        Task<EncryptionKey> CreateKeyAsync(string keyName, string keyType, int keySize);
        Task<EncryptionKey> GetKeyAsync(string keyId);
        Task<List<EncryptionKey>> GetActiveKeysAsync();
        Task<bool> RotateKeyAsync(string keyId);
        Task<bool> RevokeKeyAsync(string keyId, string reason);
        Task<bool> DeleteKeyAsync(string keyId);
        
        // Key Storage
        Task<bool> StoreKeyAsync(string keyId, byte[] keyData, bool isSecure = true);
        Task<byte[]> RetrieveKeyAsync(string keyId);
        Task<bool> BackupKeyAsync(string keyId, string backupLocation);
        Task<bool> RestoreKeyAsync(string keyId, string backupLocation);
        
        // Key Usage
        Task<bool> ValidateKeyUsageAsync(string keyId, string purpose);
        Task<bool> UpdateKeyUsageAsync(string keyId, int usageCount);
        Task<Dictionary<string, object>> GetKeyStatisticsAsync(string keyId);
        
        // Key Security
        Task<bool> EncryptKeyAsync(string keyId, string masterKeyId);
        Task<bool> SetKeyExpirationAsync(string keyId, DateTime expirationDate);
        Task<List<EncryptionKey>> GetExpiringKeysAsync(int daysThreshold);
        Task<bool> AuditKeyUsageAsync(string keyId, string operation, Guid userId);
    }
}