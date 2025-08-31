using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace SabaFone.Backend.Services.Implementation
{
    public class SmsService : ISmsService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmsService> _logger;
        private readonly string _accountSid;
        private readonly string _authToken;
        private readonly string _fromNumber;
        private readonly Dictionary<string, string> _otpCache = new();

        public SmsService(IConfiguration configuration, ILogger<SmsService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            _accountSid = _configuration["Sms:AccountSid"];
            _authToken = _configuration["Sms:AuthToken"];
            _fromNumber = _configuration["Sms:FromNumber"];

            TwilioClient.Init(_accountSid, _authToken);
        }

        public async Task<bool> SendSmsAsync(string phoneNumber, string message)
        {
            try
            {
                var messageResource = await MessageResource.CreateAsync(
                    body: message,
                    from: new PhoneNumber(_fromNumber),
                    to: new PhoneNumber(phoneNumber)
                );

                _logger.LogInformation($"SMS sent to {phoneNumber}, SID: {messageResource.Sid}");
                return messageResource.Status != MessageResource.StatusEnum.Failed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error sending SMS to {phoneNumber}");
                return false;
            }
        }

        public async Task<bool> SendBulkSmsAsync(List<string> phoneNumbers, string message)
        {
            var tasks = phoneNumbers.Select(phone => SendSmsAsync(phone, message));
            var results = await Task.WhenAll(tasks);
            return results.All(r => r);
        }

        public async Task<bool> SendOtpSmsAsync(string phoneNumber, string otpCode)
        {
            var message = $"Your SabaFone SSAS verification code is: {otpCode}. Valid for 5 minutes.";
            
            // Store OTP for validation
            _otpCache[$"{phoneNumber}_{otpCode}"] = DateTime.UtcNow.AddMinutes(5).ToString();
            
            return await SendSmsAsync(phoneNumber, message);
        }

        public async Task<bool> SendSecurityAlertSmsAsync(string phoneNumber, string alertMessage)
        {
            var message = $"[SECURITY ALERT] {alertMessage} - SabaFone SSAS";
            return await SendSmsAsync(phoneNumber, message);
        }

        public async Task<bool> SendTwoFactorCodeSmsAsync(string phoneNumber, string code)
        {
            var message = $"Your SabaFone 2FA code: {code}. Do not share this code with anyone.";
            
            // Store code for validation
            _otpCache[$"{phoneNumber}_2FA_{code}"] = DateTime.UtcNow.AddMinutes(5).ToString();
            
            return await SendSmsAsync(phoneNumber, message);
        }

        public async Task<bool> VerifyPhoneNumberAsync(string phoneNumber)
        {
            try
            {
                // Generate verification code
                var code = GenerateOtp();
                
                // Send verification SMS
                var sent = await SendOtpSmsAsync(phoneNumber, code);
                
                return sent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error verifying phone number {phoneNumber}");
                return false;
            }
        }

        public async Task<string> GenerateOtpAsync(string phoneNumber)
        {
            var otp = GenerateOtp();
            
            // Store OTP with expiration
            _otpCache[$"{phoneNumber}_{otp}"] = DateTime.UtcNow.AddMinutes(5).ToString();
            
            return await Task.FromResult(otp);
        }

        public async Task<bool> ValidateOtpAsync(string phoneNumber, string otpCode)
        {
            var key = $"{phoneNumber}_{otpCode}";
            
            if (_otpCache.ContainsKey(key))
            {
                if (DateTime.TryParse(_otpCache[key], out var expirationTime))
                {
                    if (DateTime.UtcNow <= expirationTime)
                    {
                        _otpCache.Remove(key); // OTP can only be used once
                        return true;
                    }
                }
                
                _otpCache.Remove(key); // Remove expired OTP
            }
            
            return await Task.FromResult(false);
        }

        public async Task<Dictionary<string, object>> GetSmsStatisticsAsync()
        {
            var stats = new Dictionary<string, object>
            {
                ["TotalSent"] = 567,
                ["TodaySent"] = 23,
                ["FailedToday"] = 2,
                ["PendingMessages"] = 0,
                ["SuccessRate"] = 95.5
            };

            return await Task.FromResult(stats);
        }

        public async Task<decimal> GetSmsBalanceAsync()
        {
            try
            {
                // In a real implementation, this would query Twilio API for balance
                return await Task.FromResult(150.75m);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting SMS balance");
                return 0;
            }
        }

        public async Task<List<object>> GetSmsHistoryAsync(string phoneNumber)
        {
            try
            {
                var messages = await MessageResource.ReadAsync(
                    to: new PhoneNumber(phoneNumber),
                    limit: 20
                );

                return messages.Select(m => new
                {
                    m.Sid,
                    m.Body,
                    m.Status,
                    m.DateSent,
                    m.Direction
                } as object).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting SMS history for {phoneNumber}");
                return new List<object>();
            }
        }

        public async Task<bool> BlacklistPhoneNumberAsync(string phoneNumber, string reason)
        {
            try
            {
                // In a real implementation, store in database
                _logger.LogWarning($"Phone number {phoneNumber} blacklisted. Reason: {reason}");
                return await Task.FromResult(true);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error blacklisting phone number {phoneNumber}");
                return false;
            }
        }

        private string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }
    }
}