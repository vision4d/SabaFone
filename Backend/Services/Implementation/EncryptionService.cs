using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Utils;
using SabaFone.Backend.Exceptions;

namespace SabaFone.Backend.Services.Implementation
{
    public class EncryptionService : IEncryptionService
    {
        private readonly ILogger<EncryptionService> _logger;
        private readonly IKeyManagementService _keyManagementService;
        private readonly byte[] _defaultKey;
        private readonly byte[] _defaultIV;

        public EncryptionService(
            ILogger<EncryptionService> logger,
            IKeyManagementService keyManagementService)
        {
            _logger = logger;
            _keyManagementService = keyManagementService;
            
            // Default key for development (should be from secure storage in production)
            _defaultKey = Encoding.UTF8.GetBytes("ThisIsASecretKey1234567890123456");
            _defaultIV = Encoding.UTF8.GetBytes("ThisIsAnIV123456");
        }

        public async Task<string> EncryptAsync(string plainText, string keyId = null)
        {
            try
            {
                if (string.IsNullOrEmpty(plainText))
                    return plainText;

                byte[] key = _defaultKey;
                if (!string.IsNullOrEmpty(keyId))
                {
                    key = await _keyManagementService.RetrieveKeyAsync(keyId);
                }

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _defaultIV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        using (var sw = new StreamWriter(cs))
                        {
                            await sw.WriteAsync(plainText);
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting data");
                throw;
            }
        }

        public async Task<string> DecryptAsync(string cipherText, string keyId = null)
        {
            try
            {
                if (string.IsNullOrEmpty(cipherText))
                    return cipherText;

                byte[] key = _defaultKey;
                if (!string.IsNullOrEmpty(keyId))
                {
                    key = await _keyManagementService.RetrieveKeyAsync(keyId);
                }

                var buffer = Convert.FromBase64String(cipherText);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _defaultIV;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(buffer))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var sr = new StreamReader(cs))
                    {
                        return await sr.ReadToEndAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting data");
                throw;
            }
        }

        public async Task<byte[]> EncryptBytesAsync(byte[] data, string keyId = null)
        {
            try
            {
                byte[] key = _defaultKey;
                if (!string.IsNullOrEmpty(keyId))
                {
                    key = await _keyManagementService.RetrieveKeyAsync(keyId);
                }

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _defaultIV;

                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            await cs.WriteAsync(data, 0, data.Length);
                        }
                        return ms.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting bytes");
                throw;
            }
        }

        public async Task<byte[]> DecryptBytesAsync(byte[] encryptedData, string keyId = null)
        {
            try
            {
                byte[] key = _defaultKey;
                if (!string.IsNullOrEmpty(keyId))
                {
                    key = await _keyManagementService.RetrieveKeyAsync(keyId);
                }

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = _defaultIV;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var ms = new MemoryStream(encryptedData))
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    using (var resultMs = new MemoryStream())
                    {
                        await cs.CopyToAsync(resultMs);
                        return resultMs.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting bytes");
                throw;
            }
        }

        public async Task<bool> EncryptFileAsync(string inputPath, string outputPath, string keyId = null)
        {
            try
            {
                var data = await File.ReadAllBytesAsync(inputPath);
                var encryptedData = await EncryptBytesAsync(data, keyId);
                await File.WriteAllBytesAsync(outputPath, encryptedData);

                _logger.LogInformation($"File encrypted: {inputPath} -> {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error encrypting file {inputPath}");
                return false;
            }
        }

        public async Task<bool> DecryptFileAsync(string inputPath, string outputPath, string keyId = null)
        {
            try
            {
                var encryptedData = await File.ReadAllBytesAsync(inputPath);
                var data = await DecryptBytesAsync(encryptedData, keyId);
                await File.WriteAllBytesAsync(outputPath, data);

                _logger.LogInformation($"File decrypted: {inputPath} -> {outputPath}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error decrypting file {inputPath}");
                return false;
            }
        }

        public string HashPassword(string password)
        {
            return CryptoHelper.HashPassword(password);
        }

        public bool VerifyPassword(string password, string hash)
        {
            return CryptoHelper.VerifyPassword(password, hash);
        }

        public string ComputeHash(string data, string algorithm = "SHA256")
        {
            using (var hasher = algorithm.ToUpper() switch
            {
                "SHA256" => SHA256.Create(),
                "SHA512" => SHA512.Create(),
                "SHA1" => SHA1.Create(),
                _ => SHA256.Create()
            })
            {
                var bytes = Encoding.UTF8.GetBytes(data);
                var hash = hasher.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        public string ComputeHmac(string data, string key)
        {
            using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToBase64String(hash);
            }
        }

        public async Task<string> SignDataAsync(string data, string privateKeyId)
        {
            try
            {
                var privateKey = await _keyManagementService.RetrieveKeyAsync(privateKeyId);
                
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    var dataBytes = Encoding.UTF8.GetBytes(data);
                    var signature = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    return Convert.ToBase64String(signature);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing data");
                throw;
            }
        }

        public async Task<bool> VerifySignatureAsync(string data, string signature, string publicKeyId)
        {
            try
            {
                var publicKey = await _keyManagementService.RetrieveKeyAsync(publicKeyId);
                
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPublicKey(publicKey, out _);
                    var dataBytes = Encoding.UTF8.GetBytes(data);
                    var signatureBytes = Convert.FromBase64String(signature);
                    return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying signature");
                return false;
            }
        }

        public async Task<string> GenerateEncryptionKeyAsync(int keySize = 256)
        {
            var key = new byte[keySize / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            
            return await Task.FromResult(Convert.ToBase64String(key));
        }

        public async Task<string> GenerateKeyPairAsync(string algorithm = "RSA")
        {
            if (algorithm.ToUpper() == "RSA")
            {
                using (var rsa = RSA.Create(2048))
                {
                    var privateKey = rsa.ExportRSAPrivateKey();
                    var publicKey = rsa.ExportRSAPublicKey();
                    
                    var keyPair = new
                    {
                        PrivateKey = Convert.ToBase64String(privateKey),
                        PublicKey = Convert.ToBase64String(publicKey)
                    };
                    
                    return await Task.FromResult(System.Text.Json.JsonSerializer.Serialize(keyPair));
                }
            }
            
            throw new NotSupportedException($"Algorithm {algorithm} is not supported");
        }

        public async Task<bool> ValidateKeyAsync(string keyId)
        {
            return await _keyManagementService.ValidateKeyUsageAsync(keyId, "encryption");
        }

        public async Task<byte[]> GenerateCertificateAsync(string subjectName, int validityYears = 1)
        {
            // Simplified certificate generation
            // In production, use proper X.509 certificate generation
            var cert = Encoding.UTF8.GetBytes($"CERT:{subjectName}:{DateTime.UtcNow.AddYears(validityYears)}");
            return await Task.FromResult(cert);
        }

        public async Task<bool> ValidateCertificateAsync(byte[] certificate)
        {
            // Simplified validation
            // In production, use proper X.509 certificate validation
            try
            {
                var certString = Encoding.UTF8.GetString(certificate);
                return await Task.FromResult(certString.StartsWith("CERT:"));
            }
            catch
            {
                return false;
            }
        }
    }
}