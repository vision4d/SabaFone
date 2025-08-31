using System.Threading.Tasks;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Services
{
    public interface IEncryptionService
    {
        Task<string> EncryptAsync(string data, string keyId = null);
        Task<string> DecryptAsync(string encryptedData, string keyId = null);
        Task<byte[]> EncryptBytesAsync(byte[] data, string keyId = null);
        Task<byte[]> DecryptBytesAsync(byte[] encryptedData, string keyId = null);
        Task<string> GenerateEncryptionKeyAsync(int keySize = 256);
        Task<string> SignDataAsync(string data, string privateKeyId);
        Task<bool> VerifySignatureAsync(string data, string signature, string publicKeyId);
    }
}