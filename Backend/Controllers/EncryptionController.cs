

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Encryption.Models;
using SabaFone.Backend.Exceptions;

namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class EncryptionController : ControllerBase
    {
        private readonly IEncryptionService _encryptionService;
        private readonly IKeyManagementService _keyManagementService;
        private readonly IAuditService _auditService;
        private readonly ILogger<EncryptionController> _logger;

        public EncryptionController(
            IEncryptionService encryptionService,
            IKeyManagementService keyManagementService,
            IAuditService auditService,
            ILogger<EncryptionController> logger)
        {
            _encryptionService = encryptionService;
            _keyManagementService = keyManagementService;
            _auditService = auditService;
            _logger = logger;
        }

        /// <summary>
        /// Encrypts text data
        /// </summary>
        [HttpPost("encrypt")]
        [Authorize(Roles = "Admin,SecurityOfficer,DataProtectionOfficer")]
        public async Task<IActionResult> EncryptData([FromBody] EncryptRequest request)
        {
            try
            {
                var encrypted = await _encryptionService.EncryptAsync(request.Data, request.KeyId);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "DATA_ENCRYPTED",
                    $"Data encrypted using key {request.KeyId ?? "default"}",
                    userId);

                return Ok(new { encryptedData = encrypted });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting data");
                return StatusCode(500, new { message = "An error occurred while encrypting data" });
            }
        }

        /// <summary>
        /// Decrypts text data
        /// </summary>
        [HttpPost("decrypt")]
        [Authorize(Roles = "Admin,SecurityOfficer,DataProtectionOfficer")]
        public async Task<IActionResult> DecryptData([FromBody] DecryptRequest request)
        {
            try
            {
                var decrypted = await _encryptionService.DecryptAsync(request.EncryptedData, request.KeyId);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "DATA_DECRYPTED",
                    $"Data decrypted using key {request.KeyId ?? "default"}",
                    userId);

                return Ok(new { data = decrypted });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting data");
                return StatusCode(500, new { message = "An error occurred while decrypting data" });
            }
        }

        /// <summary>
        /// Encrypts a file
        /// </summary>
        [HttpPost("encrypt-file")]
        [Authorize(Roles = "Admin,SecurityOfficer,DataProtectionOfficer")]
        public async Task<IActionResult> EncryptFile(IFormFile file, [FromQuery] string keyId = null)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest(new { message = "No file provided" });
                }

                using (var stream = file.OpenReadStream())
                {
                    var data = new byte[file.Length];
                    await stream.ReadAsync(data, 0, data.Length);
                    
                    var encrypted = await _encryptionService.EncryptBytesAsync(data, keyId);
                    
                    var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                    await _auditService.LogAsync(
                        "FILE_ENCRYPTED",
                        $"File {file.FileName} encrypted",
                        userId);

                    return File(encrypted, "application/octet-stream", $"{file.FileName}.encrypted");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting file");
                return StatusCode(500, new { message = "An error occurred while encrypting file" });
            }
        }

        /// <summary>
        /// Decrypts a file
        /// </summary>
        [HttpPost("decrypt-file")]
        [Authorize(Roles = "Admin,SecurityOfficer,DataProtectionOfficer")]
        public async Task<IActionResult> DecryptFile(IFormFile file, [FromQuery] string keyId = null)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    return BadRequest(new { message = "No file provided" });
                }

                using (var stream = file.OpenReadStream())
                {
                    var encryptedData = new byte[file.Length];
                    await stream.ReadAsync(encryptedData, 0, encryptedData.Length);
                    
                    var decrypted = await _encryptionService.DecryptBytesAsync(encryptedData, keyId);
                    
                    var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                    await _auditService.LogAsync(
                        "FILE_DECRYPTED",
                        $"File {file.FileName} decrypted",
                        userId);

                    var originalFileName = file.FileName.Replace(".encrypted", "");
                    return File(decrypted, "application/octet-stream", originalFileName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting file");
                return StatusCode(500, new { message = "An error occurred while decrypting file" });
            }
        }

        /// <summary>
        /// Gets all encryption keys
        /// </summary>
        [HttpGet("keys")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetEncryptionKeys()
        {
            try
            {
                var keys = await _keyManagementService.GetActiveKeysAsync();
                
                var response = keys.Select(k => new KeyDto
                {
                    KeyId = k.KeyId,
                    KeyName = k.KeyName,
                    KeyType = k.KeyType,
                    Algorithm = k.Algorithm,
                    KeySize = k.KeySize,
                    CreatedAt = k.CreatedAt,
                    ExpiresAt = k.ExpiresAt,
                    Status = k.Status,
                    UsageCount = k.UsageCount
                });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting encryption keys");
                return StatusCode(500, new { message = "An error occurred while getting keys" });
            }
        }

        /// <summary>
        /// Creates new encryption key
        /// </summary>
        [HttpPost("keys")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> CreateEncryptionKey([FromBody] CreateKeyRequest request)
        {
            try
            {
                var key = await _keyManagementService.CreateKeyAsync(
                    request.KeyName,
                    request.KeyType,
                    request.KeySize);

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "KEY_CREATED",
                    $"Encryption key {key.KeyName} created",
                    userId);

                return Ok(new
                {
                    keyId = key.KeyId,
                    keyName = key.KeyName,
                    message = "Key created successfully"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating encryption key");
                return StatusCode(500, new { message = "An error occurred while creating key" });
            }
        }

        /// <summary>
        /// Rotates encryption key
        /// </summary>
        [HttpPost("keys/{keyId}/rotate")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> RotateKey(string keyId)
        {
            try
            {
                var result = await _keyManagementService.RotateKeyAsync(keyId);
                
                if (!result)
                {
                    return NotFound(new { message = "Key not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "KEY_ROTATED",
                    $"Encryption key {keyId} rotated",
                    userId);

                return Ok(new { message = "Key rotated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error rotating key {keyId}");
                return StatusCode(500, new { message = "An error occurred while rotating key" });
            }
        }

        /// <summary>
        /// Revokes encryption key
        /// </summary>
        [HttpPost("keys/{keyId}/revoke")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RevokeKey(string keyId, [FromBody] RevokeKeyRequest request)
        {
            try
            {
                var result = await _keyManagementService.RevokeKeyAsync(keyId, request.Reason);
                
                if (!result)
                {
                    return NotFound(new { message = "Key not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "KEY_REVOKED",
                    $"Encryption key {keyId} revoked. Reason: {request.Reason}",
                    userId);

                return Ok(new { message = "Key revoked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error revoking key {keyId}");
                return StatusCode(500, new { message = "An error occurred while revoking key" });
            }
        }

        /// <summary>
        /// Gets key statistics
        /// </summary>
        [HttpGet("keys/{keyId}/statistics")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetKeyStatistics(string keyId)
        {
            try
            {
                var stats = await _keyManagementService.GetKeyStatisticsAsync(keyId);
                
                if (stats == null)
                {
                    return NotFound(new { message = "Key not found" });
                }

                return Ok(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting statistics for key {keyId}");
                return StatusCode(500, new { message = "An error occurred while getting statistics" });
            }
        }

        /// <summary>
        /// Backs up encryption key
        /// </summary>
        [HttpPost("keys/{keyId}/backup")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> BackupKey(string keyId, [FromBody] BackupKeyRequest request)
        {
            try
            {
                var result = await _keyManagementService.BackupKeyAsync(keyId, request.BackupLocation);
                
                if (!result)
                {
                    return NotFound(new { message = "Key not found" });
                }

                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "KEY_BACKED_UP",
                    $"Encryption key {keyId} backed up to {request.BackupLocation}",
                    userId);

                return Ok(new { message = "Key backed up successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error backing up key {keyId}");
                return StatusCode(500, new { message = "An error occurred while backing up key" });
            }
        }

        /// <summary>
        /// Gets expiring keys
        /// </summary>
        [HttpGet("keys/expiring")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GetExpiringKeys([FromQuery] int daysThreshold = 30)
        {
            try
            {
                var keys = await _keyManagementService.GetExpiringKeysAsync(daysThreshold);
                
                var response = keys.Select(k => new
                {
                    KeyId = k.KeyId,
                    KeyName = k.KeyName,
                    ExpiresAt = k.ExpiresAt,
                    DaysRemaining = (k.ExpiresAt - DateTime.UtcNow).Days
                });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting expiring keys");
                return StatusCode(500, new { message = "An error occurred while getting expiring keys" });
            }
        }

        /// <summary>
        /// Generates new encryption key
        /// </summary>
        [HttpPost("generate-key")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> GenerateKey([FromBody] GenerateKeyRequest request)
        {
            try
            {
                var key = await _encryptionService.GenerateEncryptionKeyAsync(request.KeySize);
                
                return Ok(new { key });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating key");
                return StatusCode(500, new { message = "An error occurred while generating key" });
            }
        }

        /// <summary>
        /// Signs data
        /// </summary>
        [HttpPost("sign")]
        [Authorize(Roles = "Admin,SecurityOfficer")]
        public async Task<IActionResult> SignData([FromBody] SignRequest request)
        {
            try
            {
                var signature = await _encryptionService.SignDataAsync(request.Data, request.PrivateKeyId);
                
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "DATA_SIGNED",
                    $"Data signed with key {request.PrivateKeyId}",
                    userId);

                return Ok(new { signature });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing data");
                return StatusCode(500, new { message = "An error occurred while signing data" });
            }
        }

        /// <summary>
        /// Verifies signature
        /// </summary>
        [HttpPost("verify")]
        public async Task<IActionResult> VerifySignature([FromBody] VerifyRequest request)
        {
            try
            {
                var isValid = await _encryptionService.VerifySignatureAsync(
                    request.Data,
                    request.Signature,
                    request.PublicKeyId);
                
                return Ok(new { valid = isValid });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying signature");
                return StatusCode(500, new { message = "An error occurred while verifying signature" });
            }
        }

        #region Request/Response Models

        public class EncryptRequest
        {
            public string Data { get; set; }
            public string KeyId { get; set; }
        }

        public class DecryptRequest
        {
            public string EncryptedData { get; set; }
            public string KeyId { get; set; }
        }

        public class CreateKeyRequest
        {
            public string KeyName { get; set; }
            public string KeyType { get; set; }
            public int KeySize { get; set; } = 256;
        }

        public class RevokeKeyRequest
        {
            public string Reason { get; set; }
        }

        public class BackupKeyRequest
        {
            public string BackupLocation { get; set; }
        }

        public class GenerateKeyRequest
        {
            public int KeySize { get; set; } = 256;
        }

        public class SignRequest
        {
            public string Data { get; set; }
            public string PrivateKeyId { get; set; }
        }

        public class VerifyRequest
        {
            public string Data { get; set; }
            public string Signature { get; set; }
            public string PublicKeyId { get; set; }
        }

        public class KeyDto
        {
            public Guid KeyId { get; set; }
            public string KeyName { get; set; }
            public string KeyType { get; set; }
            public string Algorithm { get; set; }
            public int KeySize { get; set; }
            public DateTime CreatedAt { get; set; }
            public DateTime ExpiresAt { get; set; }
            public string Status { get; set; }
            public int UsageCount { get; set; }
        }

        #endregion
    }
}