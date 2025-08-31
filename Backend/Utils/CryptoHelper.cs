using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace SabaFone.Backend.Utils
{
    /// <summary>
    /// Helper class for cryptographic operations used throughout SSAS
    /// </summary>
    public static class CryptoHelper
    {
        private const int SaltSize = 128 / 8; // 128 bit salt
        private const int KeySize = 256 / 8; // 256 bit key
        private const int Iterations = 10000; // PBKDF2 iterations
        private const int HashSize = 256 / 8; // SHA256 hash size

        #region Password Hashing

        /// <summary>
        /// Hashes a password using PBKDF2 with a random salt
        /// </summary>
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException(nameof(password));

            // Generate a random salt
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Hash the password
            byte[] hash = KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: Iterations,
                numBytesRequested: KeySize);

            // Combine salt and hash
            byte[] hashBytes = new byte[SaltSize + KeySize];
            Array.Copy(salt, 0, hashBytes, 0, SaltSize);
            Array.Copy(hash, 0, hashBytes, SaltSize, KeySize);

            // Convert to base64
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Verifies a password against a hash
        /// </summary>
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hashedPassword))
                return false;

            try
            {
                // Convert from base64
                byte[] hashBytes = Convert.FromBase64String(hashedPassword);

                // Extract salt
                byte[] salt = new byte[SaltSize];
                Array.Copy(hashBytes, 0, salt, 0, SaltSize);

                // Hash the input password with the same salt
                byte[] hash = KeyDerivation.Pbkdf2(
                    password: password,
                    salt: salt,
                    prf: KeyDerivationPrf.HMACSHA256,
                    iterationCount: Iterations,
                    numBytesRequested: KeySize);

                // Compare the results
                for (int i = 0; i < KeySize; i++)
                {
                    if (hashBytes[i + SaltSize] != hash[i])
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks if a password meets SSAS complexity requirements
        /// </summary>
        public static bool IsPasswordComplex(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 8)
                return false;

            // Must contain at least one uppercase letter
            if (!Regex.IsMatch(password, @"[A-Z]"))
                return false;

            // Must contain at least one lowercase letter
            if (!Regex.IsMatch(password, @"[a-z]"))
                return false;

            // Must contain at least one digit
            if (!Regex.IsMatch(password, @"\d"))
                return false;

            // Must contain at least one special character
            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+=\[{\]};:<>|./?,-]"))
                return false;

            return true;
        }

        #endregion

        #region Encryption/Decryption

        /// <summary>
        /// Encrypts a string using AES
        /// </summary>
        public static string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            byte[] keyBytes = GetKeyBytes(key);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    
                    // Combine IV and encrypted data
                    byte[] result = new byte[aes.IV.Length + encryptedBytes.Length];
                    Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                    Array.Copy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);
                    
                    return Convert.ToBase64String(result);
                }
            }
        }

        /// <summary>
        /// Decrypts a string encrypted with AES
        /// </summary>
        public static string Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            byte[] keyBytes = GetKeyBytes(key);
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Extract IV from the beginning
                byte[] iv = new byte[aes.IV.Length];
                Array.Copy(cipherBytes, 0, iv, 0, iv.Length);
                aes.IV = iv;

                // Extract encrypted data
                byte[] encryptedBytes = new byte[cipherBytes.Length - iv.Length];
                Array.Copy(cipherBytes, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }

        #endregion

        #region Hashing

        /// <summary>
        /// Computes SHA256 hash of a string
        /// </summary>
        public static string ComputeSHA256(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            using (var sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Computes SHA512 hash of a string
        /// </summary>
        public static string ComputeSHA512(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            using (var sha512 = SHA512.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = sha512.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Computes HMAC-SHA256
        /// </summary>
        public static string ComputeHMACSHA256(string message, string secret)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(secret);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                byte[] hash = hmac.ComputeHash(messageBytes);
                return Convert.ToBase64String(hash);
            }
        }

        /// <summary>
        /// Computes MD5 hash (for non-security purposes only)
        /// </summary>
        public static string ComputeMD5(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                byte[] hash = md5.ComputeHash(bytes);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        #endregion

        #region Random Generation

        /// <summary>
        /// Generates a cryptographically secure random string
        /// </summary>
        public static string GenerateRandomString(int length, bool includeSpecialChars = false)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            
            string alphabet = includeSpecialChars ? chars + specialChars : chars;
            
            var result = new StringBuilder(length);
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] buffer = new byte[sizeof(uint)];
                while (result.Length < length)
                {
                    rng.GetBytes(buffer);
                    uint num = BitConverter.ToUInt32(buffer, 0);
                    result.Append(alphabet[(int)(num % (uint)alphabet.Length)]);
                }
            }
            
            return result.ToString();
        }

        /// <summary>
        /// Generates a secure random token
        /// </summary>
        public static string GenerateToken(int byteLength = 32)
        {
            byte[] tokenBytes = new byte[byteLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        /// <summary>
        /// Generates a secure API key
        /// </summary>
        public static string GenerateApiKey()
        {
            return $"sk_{GenerateRandomString(8)}_{GenerateToken(24)}";
        }

        /// <summary>
        /// Generates a secure OTP (One-Time Password)
        /// </summary>
        public static string GenerateOTP(int length = 6)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[4];
                rng.GetBytes(bytes);
                uint num = BitConverter.ToUInt32(bytes, 0);
                uint otp = num % (uint)Math.Pow(10, length);
                return otp.ToString().PadLeft(length, '0');
            }
        }

        #endregion

        #region Digital Signatures

        /// <summary>
        /// Creates a digital signature using RSA
        /// </summary>
        public static string SignData(string data, string privateKeyXml)
        {
            using (var rsa = RSA.Create())
            {
                rsa.FromXmlString(privateKeyXml);
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signature = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signature);
            }
        }

        /// <summary>
        /// Verifies a digital signature using RSA
        /// </summary>
        public static bool VerifySignature(string data, string signature, string publicKeyXml)
        {
            try
            {
                using (var rsa = RSA.Create())
                {
                    rsa.FromXmlString(publicKeyXml);
                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    byte[] signatureBytes = Convert.FromBase64String(signature);
                    return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Generates RSA key pair
        /// </summary>
        public static (string publicKey, string privateKey) GenerateRSAKeyPair(int keySize = 2048)
        {
            using (var rsa = RSA.Create(keySize))
            {
                return (rsa.ToXmlString(false), rsa.ToXmlString(true));
            }
        }

        #endregion

        #region File Operations

        /// <summary>
        /// Computes hash of a file
        /// </summary>
        public static async Task<string> ComputeFileHashAsync(string filePath, string algorithm = "SHA256")
        {
            using (var stream = File.OpenRead(filePath))
            {
                HashAlgorithm hasher = algorithm.ToUpper() switch
                {
                    "SHA256" => SHA256.Create(),
                    "SHA512" => SHA512.Create(),
                    "MD5" => MD5.Create(),
                    _ => SHA256.Create()
                };

                using (hasher)
                {
                    byte[] hash = await Task.Run(() => hasher.ComputeHash(stream));
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        /// <summary>
        /// Encrypts a file
        /// </summary>
        public static async Task EncryptFileAsync(string inputFile, string outputFile, string key)
        {
            byte[] keyBytes = GetKeyBytes(key);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.GenerateIV();

                using (var fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (var fsOut = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    // Write IV to the beginning of the file
                    await fsOut.WriteAsync(aes.IV, 0, aes.IV.Length);

                    using (var encryptor = aes.CreateEncryptor())
                    using (var cs = new CryptoStream(fsOut, encryptor, CryptoStreamMode.Write))
                    {
                        await fsIn.CopyToAsync(cs);
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a file
        /// </summary>
        public static async Task DecryptFileAsync(string inputFile, string outputFile, string key)
        {
            byte[] keyBytes = GetKeyBytes(key);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;

                using (var fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (var fsOut = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    // Read IV from the beginning of the file
                    byte[] iv = new byte[aes.IV.Length];
                    await fsIn.ReadAsync(iv, 0, iv.Length);
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var cs = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read))
                    {
                        await cs.CopyToAsync(fsOut);
                    }
                }
            }
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Derives a key from a password
        /// </summary>
        private static byte[] GetKeyBytes(string password)
        {
            byte[] salt = Encoding.UTF8.GetBytes("SabaFone_SSAS_Salt_2024");
            return KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: 10000,
                numBytesRequested: 32);
        }

        /// <summary>
        /// Securely compares two byte arrays (timing-attack resistant)
        /// </summary>
        public static bool SecureCompare(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            uint diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        /// <summary>
        /// Converts hex string to byte array
        /// </summary>
        public static byte[] HexToBytes(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        /// <summary>
        /// Converts byte array to hex string
        /// </summary>
        public static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        #endregion
    }
}