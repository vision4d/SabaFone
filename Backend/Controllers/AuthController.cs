//1️⃣ Controllers/AuthController.cs

/*<artifacts>
<artifact identifier="auth-controller" type="application/vnd.ant.code" language="csharp" title="Controllers/AuthController.cs">
// SabaFone Security System Automation System (SSAS)
// Backend/Controllers/AuthController.cs
// وحدة التحكم في المصادقة - شركة سبأفون
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SabaFone.Backend.Data;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Services;
using SabaFone.Backend.Utils;
namespace SabaFone.Backend.Controllers
{
/// <summary>
/// وحدة التحكم في المصادقة والتفويض
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
private readonly SsasDbContext _context;
private readonly IConfiguration _configuration;
private readonly ILogger<AuthController> _logger;
private readonly IEmailService _emailService;
private readonly ISmsService _smsService;
private readonly IAuditService _auditService;
public AuthController(
        SsasDbContext context,
        IConfiguration configuration,
        ILogger<AuthController> logger,
        IEmailService emailService,
        ISmsService smsService,
        IAuditService auditService)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
        _emailService = emailService;
        _smsService = smsService;
        _auditService = auditService;
    }
    
    #region Authentication
    
    /// <summary>
    /// تسجيل الدخول / User Login
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            // Validate request
            if (!ModelState.IsValid)
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "بيانات غير صحيحة",
                    MessageEn = "Invalid data"
                });
            
            // Log login attempt
            await LogLoginAttempt(request.Username, HttpContext.Connection.RemoteIpAddress?.ToString());
            
            // Find user
            var user = await _context.Users
                .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => 
                    (u.Username == request.Username || u.Email == request.Username) &&
                    u.IsActive && !u.IsDeleted);
            
            if (user == null)
            {
                await Task.Delay(Random.Shared.Next(500, 1500)); // Prevent timing attacks
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "اسم المستخدم أو كلمة المرور غير صحيحة",
                    MessageEn = "Invalid username or password"
                });
            }
            
            // Check if account is locked
            if (user.IsLocked)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "الحساب مقفل. يرجى الاتصال بالدعم",
                    MessageEn = "Account is locked. Please contact support"
                });
            }
            
            // Verify password
            if (!SecurityHelper.VerifyPassword(request.Password, user.PasswordHash))
            {
                // Increment failed attempts
                user.FailedLoginAttempts++;
                user.LastFailedLogin = DateTime.UtcNow;
                
                // Lock account after 5 failed attempts
                if (user.FailedLoginAttempts >= 5)
                {
                    user.IsLocked = true;
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(30);
                    
                    // Send notification
                    await _emailService.SendAccountLockedEmailAsync(user.Email, user.FirstName);
                }
                
                await _context.SaveChangesAsync();
                
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "اسم المستخدم أو كلمة المرور غير صحيحة",
                    MessageEn = "Invalid username or password"
                });
            }
            
            // Check if password needs to be changed
            if (user.MustChangePassword)
            {
                return Ok(new ApiResponse<object>
                {
                    Success = false,
                    Message = "يجب تغيير كلمة المرور",
                    MessageEn = "Password change required",
                    Data = new { RequiresPasswordChange = true, UserId = user.UserId }
                });
            }
            
            // Check if 2FA is enabled
            if (user.TwoFactorEnabled && !request.TwoFactorCode.HasValue)
            {
                // Generate and send 2FA code
                var code = Random.Shared.Next(100000, 999999);
                user.TwoFactorCode = SecurityHelper.HashPassword(code.ToString());
                user.TwoFactorCodeExpiry = DateTime.UtcNow.AddMinutes(5);
                await _context.SaveChangesAsync();
                
                // Send code via SMS or email
                if (!string.IsNullOrEmpty(user.PhoneNumber))
                {
                    await _smsService.SendTwoFactorCodeAsync(user.PhoneNumber, code.ToString());
                }
                else
                {
                    await _emailService.SendTwoFactorCodeAsync(user.Email, code.ToString());
                }
                
                return Ok(new ApiResponse<object>
                {
                    Success = false,
                    Message = "تم إرسال رمز التحقق",
                    MessageEn = "Verification code sent",
                    Data = new { RequiresTwoFactor = true }
                });
            }
            
            // Verify 2FA code if provided
            if (user.TwoFactorEnabled && request.TwoFactorCode.HasValue)
            {
                if (user.TwoFactorCodeExpiry == null || user.TwoFactorCodeExpiry < DateTime.UtcNow)
                {
                    return Unauthorized(new ApiResponse<object>
                    {
                        Success = false,
                        Message = "رمز التحقق منتهي الصلاحية",
                        MessageEn = "Verification code expired"
                    });
                }
                
                if (!SecurityHelper.VerifyPassword(request.TwoFactorCode.Value.ToString(), user.TwoFactorCode))
                {
                    return Unauthorized(new ApiResponse<object>
                    {
                        Success = false,
                        Message = "رمز التحقق غير صحيح",
                        MessageEn = "Invalid verification code"
                    });
                }
                
                // Clear 2FA code
                user.TwoFactorCode = null;
                user.TwoFactorCodeExpiry = null;
            }
            
            // Generate tokens
            var (accessToken, refreshToken) = await GenerateTokens(user);
            
            // Create session
            var session = new UserSession
            {
                UserId = user.UserId,
                Token = refreshToken,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                DeviceInfo = request.DeviceInfo,
                ExpiresAt = DateTime.UtcNow.AddDays(30),
                IsActive = true
            };
            
            _context.UserSessions.Add(session);
            
            // Update user login info
            user.LastLogin = DateTime.UtcNow;
            user.FailedLoginAttempts = 0;
            user.LastFailedLogin = null;
            
            await _context.SaveChangesAsync();
            
            // Audit log
            await _auditService.LogAsync("AUTH_LOGIN", "User logged in", user.UserId);
            
            // Prepare response
            var roles = user.UserRoles.Select(ur => ur.Role.RoleName).ToList();
            var permissions = await GetUserPermissions(user.UserId);
            
            return Ok(new ApiResponse<LoginResponse>
            {
                Success = true,
                Message = "تم تسجيل الدخول بنجاح",
                MessageEn = "Login successful",
                Data = new LoginResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = 3600,
                    User = new UserInfo
                    {
                        UserId = user.UserId,
                        Username = user.Username,
                        Email = user.Email,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        FullName = $"{user.FirstName} {user.LastName}",
                        Roles = roles,
                        Permissions = permissions,
                        ProfilePicture = user.ProfilePicture,
                        Language = user.PreferredLanguage
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error for user: {Username}", request.Username);
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    /// <summary>
    /// تسجيل الخروج / Logout
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userId = GetUserId();
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            
            // Invalidate session
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.UserId == userId && s.IsActive);
            
            if (session != null)
            {
                session.IsActive = false;
                session.IsRevoked = true;
                session.RevokedAt = DateTime.UtcNow;
                session.RevokedReason = "User logout";
            }
            
            await _context.SaveChangesAsync();
            
            // Audit log
            await _auditService.LogAsync("AUTH_LOGOUT", "User logged out", userId);
            
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "تم تسجيل الخروج بنجاح",
                MessageEn = "Logout successful"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout error");
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    /// <summary>
    /// تحديث رمز الوصول / Refresh Token
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            // Find session
            var session = await _context.UserSessions
                .Include(s => s.User)
                    .ThenInclude(u => u.UserRoles)
                        .ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(s => 
                    s.Token == request.RefreshToken && 
                    s.IsActive && 
                    !s.IsRevoked);
            
            if (session == null || session.ExpiresAt < DateTime.UtcNow)
            {
                return Unauthorized(new ApiResponse<object>
                {
                    Success = false,
                    Message = "رمز التحديث غير صالح أو منتهي الصلاحية",
                    MessageEn = "Invalid or expired refresh token"
                });
            }
            
            // Generate new tokens
            var (accessToken, refreshToken) = await GenerateTokens(session.User);
            
            // Update session
            session.Token = refreshToken;
            session.RefreshedAt = DateTime.UtcNow;
            session.ExpiresAt = DateTime.UtcNow.AddDays(30);
            
            await _context.SaveChangesAsync();
            
            // Prepare response
            var roles = session.User.UserRoles.Select(ur => ur.Role.RoleName).ToList();
            var permissions = await GetUserPermissions(session.User.UserId);
            
            return Ok(new ApiResponse<LoginResponse>
            {
                Success = true,
                Message = "تم تحديث رمز الوصول",
                MessageEn = "Token refreshed",
                Data = new LoginResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = 3600,
                    User = new UserInfo
                    {
                        UserId = session.User.UserId,
                        Username = session.User.Username,
                        Email = session.User.Email,
                        FirstName = session.User.FirstName,
                        LastName = session.User.LastName,
                        FullName = $"{session.User.FirstName} {session.User.LastName}",
                        Roles = roles,
                        Permissions = permissions,
                        ProfilePicture = session.User.ProfilePicture,
                        Language = session.User.PreferredLanguage
                    }
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Refresh token error");
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    #endregion
    
    #region Password Management
    
    /// <summary>
    /// تغيير كلمة المرور / Change Password
    /// </summary>
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        try
        {
            var userId = GetUserId();
            var user = await _context.Users.FindAsync(userId);
            
            if (user == null)
                return NotFound(new ApiResponse<object>
                {
                    Success = false,
                    Message = "المستخدم غير موجود",
                    MessageEn = "User not found"
                });
            
            // Verify current password
            if (!SecurityHelper.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "كلمة المرور الحالية غير صحيحة",
                    MessageEn = "Current password is incorrect"
                });
            }
            
            // Validate new password
            var passwordStrength = SecurityHelper.CheckPasswordStrength(request.NewPassword);
            if (passwordStrength < SecurityHelper.PasswordStrength.Fair)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "كلمة المرور الجديدة ضعيفة جداً",
                    MessageEn = "New password is too weak"
                });
            }
            
            // Check password history
            var passwordHistory = await _context.UserActivities
                .Where(a => a.UserId == userId && a.ActivityType == "PASSWORD_CHANGE")
                .OrderByDescending(a => a.Timestamp)
                .Take(5)
                .Select(a => a.Details)
                .ToListAsync();
            
            foreach (var oldPasswordHash in passwordHistory)
            {
                if (!string.IsNullOrEmpty(oldPasswordHash) && 
                    SecurityHelper.VerifyPassword(request.NewPassword, oldPasswordHash))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        Success = false,
                        Message = "لا يمكن استخدام كلمة مرور مستخدمة سابقاً",
                        MessageEn = "Cannot reuse previous passwords"
                    });
                }
            }
            
            // Update password
            user.PasswordHash = SecurityHelper.HashPassword(request.NewPassword);
            user.PasswordChangedAt = DateTime.UtcNow;
            user.MustChangePassword = false;
            
            // Log password change
            _context.UserActivities.Add(new UserActivity
            {
                UserId = userId,
                ActivityType = "PASSWORD_CHANGE",
                Description = "Password changed",
                Details = user.PasswordHash,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = Request.Headers["User-Agent"].ToString(),
                Timestamp = DateTime.UtcNow
            });
            
            await _context.SaveChangesAsync();
            
            // Send notification
            await _emailService.SendPasswordChangedEmailAsync(user.Email, user.FirstName);
            
            // Audit log
            await _auditService.LogAsync("AUTH_PASSWORD_CHANGE", "Password changed", userId);
            
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "تم تغيير كلمة المرور بنجاح",
                MessageEn = "Password changed successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Change password error");
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    /// <summary>
    /// طلب إعادة تعيين كلمة المرور / Request Password Reset
    /// </summary>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        try
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.Email && u.IsActive);
            
            // Always return success to prevent user enumeration
            if (user == null)
            {
                await Task.Delay(Random.Shared.Next(500, 1500));
                return Ok(new ApiResponse<object>
                {
                    Success = true,
                    Message = "إذا كان البريد الإلكتروني مسجل، سيتم إرسال رابط إعادة التعيين",
                    MessageEn = "If the email is registered, a reset link will be sent"
                });
            }
            
            // Generate reset token
            var resetToken = SecurityHelper.GenerateSecureToken();
            
            // Save token
            var userToken = new UserToken
            {
                UserId = user.UserId,
                Token = SecurityHelper.HashPassword(resetToken),
                TokenType = TokenType.PasswordReset,
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                CreatedAt = DateTime.UtcNow
            };
            
            _context.UserTokens.Add(userToken);
            await _context.SaveChangesAsync();
            
            // Send reset email
            var resetLink = $"{_configuration["AppUrl"]}/reset-password?token={resetToken}";
            await _emailService.SendPasswordResetEmailAsync(user.Email, user.FirstName, resetLink);
            
            // Audit log
            await _auditService.LogAsync("AUTH_PASSWORD_RESET_REQUEST", $"Password reset requested for {user.Email}", user.UserId);
            
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "إذا كان البريد الإلكتروني مسجل، سيتم إرسال رابط إعادة التعيين",
                MessageEn = "If the email is registered, a reset link will be sent"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Forgot password error");
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    /// <summary>
    /// إعادة تعيين كلمة المرور / Reset Password
    /// </summary>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            // Find token
            var userTokens = await _context.UserTokens
                .Include(t => t.User)
                .Where(t => t.TokenType == TokenType.PasswordReset && 
                           t.ExpiresAt > DateTime.UtcNow &&
                           !t.IsUsed)
                .ToListAsync();
            
            UserToken? validToken = null;
            foreach (var token in userTokens)
            {
                if (SecurityHelper.VerifyPassword(request.Token, token.Token))
                {
                    validToken = token;
                    break;
                }
            }
            
            if (validToken == null)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "رمز إعادة التعيين غير صالح أو منتهي الصلاحية",
                    MessageEn = "Invalid or expired reset token"
                });
            }
            
            // Validate new password
            var passwordStrength = SecurityHelper.CheckPasswordStrength(request.NewPassword);
            if (passwordStrength < SecurityHelper.PasswordStrength.Fair)
            {
                return BadRequest(new ApiResponse<object>
                {
                    Success = false,
                    Message = "كلمة المرور الجديدة ضعيفة جداً",
                    MessageEn = "New password is too weak"
                });
            }
            
            // Update password
            var user = validToken.User;
            user.PasswordHash = SecurityHelper.HashPassword(request.NewPassword);
            user.PasswordChangedAt = DateTime.UtcNow;
            user.MustChangePassword = false;
            
            // Mark token as used
            validToken.IsUsed = true;
            validToken.UsedAt = DateTime.UtcNow;
            
            await _context.SaveChangesAsync();
            
            // Send notification
            await _emailService.SendPasswordResetSuccessEmailAsync(user.Email, user.FirstName);
            
            // Audit log
            await _auditService.LogAsync("AUTH_PASSWORD_RESET", "Password reset completed", user.UserId);
            
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = "تم إعادة تعيين كلمة المرور بنجاح",
                MessageEn = "Password reset successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Reset password error");
            return StatusCode(500, new ApiResponse<object>
            {
                Success = false,
                Message = "حدث خطأ في النظام",
                MessageEn = "System error occurred"
            });
        }
    }
    
    #endregion
    
    #region Helper Methods
    
    private async Task<(string AccessToken, string RefreshToken)> GenerateTokens(User user)
    {
        // Get roles
        var roles = user.UserRoles.Select(ur => ur.Role.RoleName).ToList();
        
        // Generate access token
        var accessToken = SecurityHelper.GenerateJwtToken(
            user.UserId.ToString(),
            user.Username,
            roles,
            _configuration["Jwt:SecretKey"],
            _configuration["Jwt:Issuer"],
            _configuration["Jwt:Audience"],
            60 // 1 hour
        );
        
        // Generate refresh token
        var refreshToken = SecurityHelper.GenerateSecureToken();
        
        return (accessToken, refreshToken);
    }
    
    private async Task<List<string>> GetUserPermissions(Guid userId)
    {
        var permissions = await _context.UserPermissions
            .Where(up => up.UserId == userId && up.IsGranted)
            .Select(up => up.Permission.PermissionName)
            .ToListAsync();
        
        var rolePermissions = await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Where(rp => rp.IsGranted)
            .Select(rp => rp.Permission.PermissionName)
            .ToListAsync();
        
        return permissions.Union(rolePermissions).Distinct().ToList();
    }
    
    private async Task LogLoginAttempt(string username, string? ipAddress)
    {
        var attempt = new UserLoginAttempt
        {
            Username = username,
            IpAddress = ipAddress,
            UserAgent = Request.Headers["User-Agent"].ToString(),
            AttemptTime = DateTime.UtcNow
        };
        
        _context.UserLoginAttempts.Add(attempt);
        await _context.SaveChangesAsync();
    }
    
    private Guid GetUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.Parse(userIdClaim ?? Guid.Empty.ToString());
    }
    
    #endregion
    
    #region DTOs
    
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public int? TwoFactorCode { get; set; }
        public string? DeviceInfo { get; set; }
    }
    
    public class LoginResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public int ExpiresIn { get; set; }
        public UserInfo User { get; set; } = new();
    }
    
    public class UserInfo
    {
        public Guid UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public List<string> Roles { get; set; } = new();
        public List<string> Permissions { get; set; } = new();
        public string? ProfilePicture { get; set; }
        public string? Language { get; set; }
    }
    
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
    
    public class ChangePasswordRequest
    {
        public string CurrentPassword { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
    
    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }
    
    public class ResetPasswordRequest
    {
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
    
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? MessageEn { get; set; }
        public T? Data { get; set; }
        public List<string>? Errors { get; set; }
    }
    
    #endregion
}}
</artifact>
</artifacts>*/
/*
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Utils;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly IAuditService _auditService;
        private readonly ISecurityService _securityService;
        private readonly INotificationService _notificationService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IUserService userService,
            IAuditService auditService,
            ISecurityService securityService,
            INotificationService notificationService,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _auditService = auditService;
            _securityService = securityService;
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticates user and returns JWT token
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                // Validate request
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Get client IP
                var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                var userAgent = Request.Headers["User-Agent"].ToString();

                // Authenticate user
                var result = await _authService.AuthenticateAsync(request.Username, request.Password);
                
                if (!result.Success)
                {
                    // Log failed attempt
                    await _securityService.LogSecurityEventAsync(new
                    {
                        EventType = "LOGIN_FAILED",
                        Username = request.Username,
                        SourceIP = clientIp,
                        UserAgent = userAgent,
                        Reason = result.Error,
                        Timestamp = DateTime.UtcNow
                    });

                    await _auditService.LogAsync(
                        "LOGIN_FAILED",
                        $"Failed login attempt for user: {request.Username} from IP: {clientIp}");

                    return Unauthorized(new { message = result.Error });
                }

                // Generate token
                var token = await _authService.GenerateTokenAsync(result.User);

                // Log successful login
                await _auditService.LogAsync(
                    "LOGIN_SUCCESS",
                    $"User {result.User.Username} logged in successfully",
                    result.User.UserId);

                await _securityService.LogSecurityEventAsync(new
                {
                    EventType = "LOGIN_SUCCESS",
                    UserId = result.User.UserId,
                    Username = result.User.Username,
                    SourceIP = clientIp,
                    UserAgent = userAgent,
                    Timestamp = DateTime.UtcNow
                });

                // Send login notification
                await _notificationService.SendLoginAlertAsync(
                    result.User.UserId,
                    clientIp,
                    GetLocationFromIp(clientIp));

                return Ok(new LoginResponse
                {
                    Token = token.Token,
                    RefreshToken = token.RefreshToken,
                    ExpiresIn = token.ExpiresIn,
                    User = new UserInfo
                    {
                        UserId = result.User.UserId,
                        Username = result.User.Username,
                        Email = result.User.Email,
                        FullName = result.User.FullName,
                        Roles = result.User.Roles,
                        Permissions = result.User.Permissions
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, new { message = "An error occurred during login" });
            }
        }

        /// <summary>
        /// Multi-factor authentication
        /// </summary>
        [HttpPost("mfa/verify")]
        [Authorize]
        public async Task<IActionResult> VerifyMfa([FromBody] MfaVerificationRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                var isValid = await _authService.ValidateMfaCodeAsync(userId, request.Code);
                
                if (!isValid)
                {
                    await _auditService.LogAsync(
                        "MFA_FAILED",
                        $"Invalid MFA code for user {userId}",
                        userId);
                    
                    return Unauthorized(new { message = "Invalid MFA code" });
                }

                // Mark session as MFA verified
                var token = await _authService.GenerateMfaTokenAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_SUCCESS",
                    $"MFA verification successful for user {userId}",
                    userId);

                return Ok(new { mfaToken = token, verified = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during MFA verification");
                return StatusCode(500, new { message = "An error occurred during MFA verification" });
            }
        }

        /// <summary>
        /// Enables MFA for user
        /// </summary>
        [HttpPost("mfa/enable")]
        [Authorize]
        public async Task<IActionResult> EnableMfa()
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                var result = await _authService.EnableMfaAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_ENABLED",
                    $"MFA enabled for user {userId}",
                    userId);

                return Ok(new
                {
                    secret = result.Secret,
                    qrCode = result.QrCode,
                    backupCodes = result.BackupCodes
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enabling MFA");
                return StatusCode(500, new { message = "An error occurred while enabling MFA" });
            }
        }

        /// <summary>
        /// Disables MFA for user
        /// </summary>
        [HttpPost("mfa/disable")]
        [Authorize]
        public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                // Verify password before disabling MFA
                var user = await _userService.GetUserByIdAsync(userId);
                if (!CryptoHelper.VerifyPassword(request.Password, user.PasswordHash))
                {
                    return Unauthorized(new { message = "Invalid password" });
                }
                
                await _authService.DisableMfaAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_DISABLED",
                    $"MFA disabled for user {userId}",
                    userId);

                await _notificationService.SendNotificationAsync(
                    userId,
                    "MFA Disabled",
                    "Two-factor authentication has been disabled for your account",
                    "warning");

                return Ok(new { message = "MFA disabled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling MFA");
                return StatusCode(500, new { message = "An error occurred while disabling MFA" });
            }
        }

        /// <summary>
        /// Refreshes authentication token
        /// </summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var result = await _authService.RefreshTokenAsync(request.RefreshToken);
                
                if (!result.Success)
                {
                    return Unauthorized(new { message = "Invalid refresh token" });
                }

                await _auditService.LogAsync(
                    "TOKEN_REFRESHED",
                    $"Token refreshed for user {result.UserId}",
                    result.UserId);

                return Ok(new
                {
                    token = result.Token,
                    refreshToken = result.RefreshToken,
                    expiresIn = result.ExpiresIn
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return StatusCode(500, new { message = "An error occurred while refreshing token" });
            }
        }

        /// <summary>
        /// Logs out user
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                
                await _authService.RevokeTokenAsync(token);
                
                await _auditService.LogAsync(
                    "LOGOUT",
                    $"User {userId} logged out",
                    userId);

                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new { message = "An error occurred during logout" });
            }
        }

        /// <summary>
        /// Changes user password
        /// </summary>
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                // Verify current password
                var user = await _userService.GetUserByIdAsync(userId);
                if (!CryptoHelper.VerifyPassword(request.CurrentPassword, user.PasswordHash))
                {
                    return BadRequest(new { message = "Current password is incorrect" });
                }

                // Validate new password
                if (!CryptoHelper.IsPasswordComplex(request.NewPassword))
                {
                    return BadRequest(new { message = "New password does not meet complexity requirements" });
                }

                // Change password
                await _authService.ChangePasswordAsync(userId, request.NewPassword);
                
                await _auditService.LogAsync(
                    "PASSWORD_CHANGED",
                    $"Password changed for user {userId}",
                    userId);

                await _notificationService.SendNotificationAsync(
                    userId,
                    "Password Changed",
                    "Your password has been changed successfully",
                    "info");

                return Ok(new { message = "Password changed successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, new { message = "An error occurred while changing password" });
            }
        }

        /// <summary>
        /// Initiates password reset
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            try
            {
                var user = await _userService.GetUserByEmailAsync(request.Email);
                
                if (user != null)
                {
                    var resetToken = await _authService.GeneratePasswordResetTokenAsync(user.UserId);
                    
                    // Send reset email
                    await _notificationService.SendNotificationAsync(
                        user.UserId,
                        "Password Reset",
                        $"Your password reset code is: {resetToken}",
                        "info");
                    
                    await _auditService.LogAsync(
                        "PASSWORD_RESET_REQUESTED",
                        $"Password reset requested for user {user.Email}");
                }

                // Always return success to prevent email enumeration
                return Ok(new { message = "If the email exists, a reset link has been sent" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset request");
                return StatusCode(500, new { message = "An error occurred while processing your request" });
            }
        }

        /// <summary>
        /// Resets password with token
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            try
            {
                // Validate new password
                if (!CryptoHelper.IsPasswordComplex(request.NewPassword))
                {
                    return BadRequest(new { message = "Password does not meet complexity requirements" });
                }

                var result = await _authService.ResetPasswordAsync(request.Token, request.NewPassword);
                
                if (!result.Success)
                {
                    return BadRequest(new { message = result.Error });
                }

                await _auditService.LogAsync(
                    "PASSWORD_RESET",
                    $"Password reset for user {result.UserId}",
                    result.UserId);

                return Ok(new { message = "Password reset successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return StatusCode(500, new { message = "An error occurred while resetting password" });
            }
        }

        /// <summary>
        /// Gets current user info
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                var user = await _userService.GetUserByIdAsync(userId);
                
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                return Ok(new UserInfo
                {
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = user.UserRoles?.Select(ur => ur.Role.Name).ToList(),
                    LastLogin = user.LastLogin,
                    MfaEnabled = user.MfaEnabled
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting current user");
                return StatusCode(500, new { message = "An error occurred while getting user info" });
            }
        }

        /// <summary>
        /// Validates token
        /// </summary>
        [HttpPost("validate")]
        [AllowAnonymous]
        public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest request)
        {
            try
            {
                var isValid = await _authService.ValidateTokenAsync(request.Token);
                
                return Ok(new { valid = isValid });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return StatusCode(500, new { message = "An error occurred while validating token" });
            }
        }

        /// <summary>
        /// Gets active sessions
        /// </summary>
        [HttpGet("sessions")]
        [Authorize]
        public async Task<IActionResult> GetActiveSessions()
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                var sessions = await _authService.GetActiveSessionsAsync(userId);
                
                return Ok(sessions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active sessions");
                return StatusCode(500, new { message = "An error occurred while getting sessions" });
            }
        }

        /// <summary>
        /// Revokes a session
        /// </summary>
        [HttpDelete("sessions/{sessionId}")]
        [Authorize]
        public async Task<IActionResult> RevokeSession(Guid sessionId)
        {
            try
            {
                var userId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                await _authService.RevokeSessionAsync(sessionId, userId);
                
                await _auditService.LogAsync(
                    "SESSION_REVOKED",
                    $"Session {sessionId} revoked for user {userId}",
                    userId);

                return Ok(new { message = "Session revoked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking session");
                return StatusCode(500, new { message = "An error occurred while revoking session" });
            }
        }

        private string GetLocationFromIp(string ipAddress)
        {
            // In production, use IP geolocation service
            return "Unknown Location";
        }

        #region Request/Response Models

        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        public class LoginResponse
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
            public int ExpiresIn { get; set; }
            public UserInfo User { get; set; }
        }

        public class UserInfo
        {
            public Guid UserId { get; set; }
            public string Username { get; set; }
            public string Email { get; set; }
            public string FullName { get; set; }
            public List<string> Roles { get; set; }
            public List<string> Permissions { get; set; }
            public DateTime? LastLogin { get; set; }
            public bool MfaEnabled { get; set; }
        }

        public class MfaVerificationRequest
        {
            public string Code { get; set; }
        }

        public class DisableMfaRequest
        {
            public string Password { get; set; }
        }

        public class RefreshTokenRequest
        {
            public string RefreshToken { get; set; }
        }

        public class ChangePasswordRequest
        {
            public string CurrentPassword { get; set; }
            public string NewPassword { get; set; }
        }

        public class ForgotPasswordRequest
        {
            public string Email { get; set; }
        }

        public class ResetPasswordRequest
        {
            public string Token { get; set; }
            public string NewPassword { get; set; }
        }

        public class ValidateTokenRequest
        {
            public string Token { get; set; }
        }

        #endregion
    }
}*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Utils;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly IAuditService _auditService;
        private readonly ISecurityService _securityService;
        private readonly INotificationService _notificationService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IUserService userService,
            IAuditService auditService,
            ISecurityService securityService,
            INotificationService notificationService,
            ILogger<AuthController> logger)
        {
            _authService = authService;
            _userService = userService;
            _auditService = auditService;
            _securityService = securityService;
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticates user and returns JWT token
        /// </summary>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                // Validate request
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                // Get client IP
                var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
                var userAgent = Request.Headers["User-Agent"].ToString();

                // Authenticate user
                var result = await _authService.AuthenticateAsync(request.Username, request.Password);
                
                if (!result.Success)
                {
                    // Log failed attempt
                    await _securityService.LogSecurityEventAsync(new
                    {
                        EventType = "LOGIN_FAILED",
                        Username = request.Username,
                        SourceIP = clientIp,
                        UserAgent = userAgent,
                        Reason = result.Error,
                        Timestamp = DateTime.UtcNow
                    });

                    await _auditService.LogAsync(
                        "LOGIN_FAILED",
                        $"Failed login attempt for user: {request.Username} from IP: {clientIp}");

                    return Unauthorized(new { message = result.Error });
                }

                // Generate token
                var token = await _authService.GenerateTokenAsync(result.User);

                // Log successful login
                await _auditService.LogAsync(
                    "LOGIN_SUCCESS",
                    $"User {result.User.Username} logged in successfully",
                    result.User.UserId);

                await _securityService.LogSecurityEventAsync(new
                {
                    EventType = "LOGIN_SUCCESS",
                    UserId = result.User.UserId,
                    Username = result.User.Username,
                    SourceIP = clientIp,
                    UserAgent = userAgent,
                    Timestamp = DateTime.UtcNow
                });

                // Send login notification
                await _notificationService.SendLoginAlertAsync(
                    result.User.UserId,
                    clientIp,
                    GetLocationFromIp(clientIp));

                return Ok(new LoginResponse
                {
                    Token = token.Token,
                    RefreshToken = token.RefreshToken,
                    ExpiresIn = token.ExpiresIn,
                    User = new UserInfo
                    {
                        UserId = result.User.UserId,
                        Username = result.User.Username,
                        Email = result.User.Email,
                        FullName = result.User.FullName,
                        Roles = result.User.Roles,
                        Permissions = result.User.Permissions
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return StatusCode(500, new { message = "An error occurred during login" });
            }
        }

        /// <summary>
        /// Multi-factor authentication
        /// </summary>
        [HttpPost("mfa/verify")]
        [Authorize]
        public async Task<IActionResult> VerifyMfa([FromBody] MfaVerificationRequest request)
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format in MFA verification: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                var isValid = await _authService.ValidateMfaCodeAsync(userId, request.Code);
                
                if (!isValid)
                {
                    await _auditService.LogAsync(
                        "MFA_FAILED",
                        $"Invalid MFA code for user {userId}",
                        userId);
                    
                    return Unauthorized(new { message = "Invalid MFA code" });
                }

                // Mark session as MFA verified
                var token = await _authService.GenerateMfaTokenAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_SUCCESS",
                    $"MFA verification successful for user {userId}",
                    userId);

                return Ok(new { mfaToken = token, verified = true });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during MFA verification");
                return StatusCode(500, new { message = "An error occurred during MFA verification" });
            }
        }

        /// <summary>
        /// Enables MFA for user
        /// </summary>
        [HttpPost("mfa/enable")]
        [Authorize]
        public async Task<IActionResult> EnableMfa()
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when enabling MFA: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                var result = await _authService.EnableMfaAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_ENABLED",
                    $"MFA enabled for user {userId}",
                    userId);

                return Ok(new
                {
                    secret = result.Secret,
                    qrCode = result.QrCode,
                    backupCodes = result.BackupCodes
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enabling MFA");
                return StatusCode(500, new { message = "An error occurred while enabling MFA" });
            }
        }

        /// <summary>
        /// Disables MFA for user
        /// </summary>
        [HttpPost("mfa/disable")]
        [Authorize]
        public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when disabling MFA: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                // Verify password before disabling MFA
                var user = await _userService.GetUserByIdAsync(userId);
                if (!CryptoHelper.VerifyPassword(request.Password, user.PasswordHash))
                {
                    return Unauthorized(new { message = "Invalid password" });
                }
                
                await _authService.DisableMfaAsync(userId);
                
                await _auditService.LogAsync(
                    "MFA_DISABLED",
                    $"MFA disabled for user {userId}",
                    userId);

                await _notificationService.SendNotificationAsync(
                    userId,
                    "MFA Disabled",
                    "Two-factor authentication has been disabled for your account",
                    "warning");

                return Ok(new { message = "MFA disabled successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling MFA");
                return StatusCode(500, new { message = "An error occurred while disabling MFA" });
            }
        }

        /// <summary>
        /// Refreshes authentication token
        /// </summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var result = await _authService.RefreshTokenAsync(request.RefreshToken);
                
                if (!result.Success)
                {
                    return Unauthorized(new { message = "Invalid refresh token" });
                }

                await _auditService.LogAsync(
                    "TOKEN_REFRESHED",
                    $"Token refreshed for user {result.UserId}",
                    result.UserId);

                return Ok(new
                {
                    token = result.Token,
                    refreshToken = result.RefreshToken,
                    expiresIn = result.ExpiresIn
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error refreshing token");
                return StatusCode(500, new { message = "An error occurred while refreshing token" });
            }
        }

        /// <summary>
        /// Logs out user
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format during logout: {User.FindFirst("UserId")?.Value}",
                        null);
                    // نستخدم Guid.Empty لتسجيل الحدث دون تأثير على النظام
                    userId = Guid.Empty;
                }
                
                var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                
                await _authService.RevokeTokenAsync(token);
                
                await _auditService.LogAsync(
                    "LOGOUT",
                    $"User {userId} logged out",
                    userId);

                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new { message = "An error occurred during logout" });
            }
        }

        /// <summary>
        /// Changes user password
        /// </summary>
        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when changing password: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                // Verify current password
                var user = await _userService.GetUserByIdAsync(userId);
                if (!CryptoHelper.VerifyPassword(request.CurrentPassword, user.PasswordHash))
                {
                    return BadRequest(new { message = "Current password is incorrect" });
                }

                // Validate new password
                if (!CryptoHelper.IsPasswordComplex(request.NewPassword))
                {
                    return BadRequest(new { message = "New password does not meet complexity requirements" });
                }

                // Change password
                await _authService.ChangePasswordAsync(userId, request.NewPassword);
                
                await _auditService.LogAsync(
                    "PASSWORD_CHANGED",
                    $"Password changed for user {userId}",
                    userId);

                await _notificationService.SendNotificationAsync(
                    userId,
                    "Password Changed",
                    "Your password has been changed successfully",
                    "info");

                return Ok(new { message = "Password changed successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error changing password");
                return StatusCode(500, new { message = "An error occurred while changing password" });
            }
        }

        /// <summary>
        /// Initiates password reset
        /// </summary>
        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            try
            {
                var user = await _userService.GetUserByEmailAsync(request.Email);
                
                if (user != null)
                {
                    var resetToken = await _authService.GeneratePasswordResetTokenAsync(user.UserId);
                    
                    // Send reset email
                    await _notificationService.SendNotificationAsync(
                        user.UserId,
                        "Password Reset",
                        $"Your password reset code is: {resetToken}",
                        "info");
                    
                    await _auditService.LogAsync(
                        "PASSWORD_RESET_REQUESTED",
                        $"Password reset requested for user {user.Email}");
                }

                // Always return success to prevent email enumeration
                return Ok(new { message = "If the email exists, a reset link has been sent" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset request");
                return StatusCode(500, new { message = "An error occurred while processing your request" });
            }
        }

        /// <summary>
        /// Resets password with token
        /// </summary>
        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            try
            {
                // Validate new password
                if (!CryptoHelper.IsPasswordComplex(request.NewPassword))
                {
                    return BadRequest(new { message = "Password does not meet complexity requirements" });
                }

                var result = await _authService.ResetPasswordAsync(request.Token, request.NewPassword);
                
                if (!result.Success)
                {
                    return BadRequest(new { message = result.Error });
                }

                await _auditService.LogAsync(
                    "PASSWORD_RESET",
                    $"Password reset for user {result.UserId}",
                    result.UserId);

                return Ok(new { message = "Password reset successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password");
                return StatusCode(500, new { message = "An error occurred while resetting password" });
            }
        }

        /// <summary>
        /// Gets current user info
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when fetching current user: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                var user = await _userService.GetUserByIdAsync(userId);
                
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                return Ok(new UserInfo
                {
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = user.UserRoles?.Select(ur => ur.Role.Name).ToList(),
                    LastLogin = user.LastLogin,
                    MfaEnabled = user.MfaEnabled
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting current user");
                return StatusCode(500, new { message = "An error occurred while getting user info" });
            }
        }

        /// <summary>
        /// Validates token
        /// </summary>
        [HttpPost("validate")]
        [AllowAnonymous]
        public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest request)
        {
            try
            {
                var isValid = await _authService.ValidateTokenAsync(request.Token);
                
                return Ok(new { valid = isValid });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
                return StatusCode(500, new { message = "An error occurred while validating token" });
            }
        }

        /// <summary>
        /// Gets active sessions
        /// </summary>
        [HttpGet("sessions")]
        [Authorize]
        public async Task<IActionResult> GetActiveSessions()
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when fetching active sessions: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                var sessions = await _authService.GetActiveSessionsAsync(userId);
                
                return Ok(sessions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting active sessions");
                return StatusCode(500, new { message = "An error occurred while getting sessions" });
            }
        }

        /// <summary>
        /// Revokes a session
        /// </summary>
        [HttpDelete("sessions/{sessionId}")]
        [Authorize]
        public async Task<IActionResult> RevokeSession(Guid sessionId)
        {
            try
            {
                Guid userId;
                if (!Guid.TryParse(User.FindFirst("UserId")?.Value, out userId))
                {
                    await _auditService.LogAsync(
                        "INVALID_USER_ID",
                        $"Invalid user ID format when revoking session: {User.FindFirst("UserId")?.Value}",
                        null);
                    return BadRequest(new { message = "Invalid user ID format" });
                }
                
                await _authService.RevokeSessionAsync(sessionId, userId);
                
                await _auditService.LogAsync(
                    "SESSION_REVOKED",
                    $"Session {sessionId} revoked for user {userId}",
                    userId);

                return Ok(new { message = "Session revoked successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error revoking session");
                return StatusCode(500, new { message = "An error occurred while revoking session" });
            }
        }

        private string GetLocationFromIp(string ipAddress)
        {
            // In production, use IP geolocation service
            return "Unknown Location";
        }

        #region Request/Response Models

        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }

        public class LoginResponse
        {
            public string Token { get; set; }
            public string RefreshToken { get; set; }
            public int ExpiresIn { get; set; }
            public UserInfo User { get; set; }
        }

        public class UserInfo
        {
            public Guid UserId { get; set; }
            public string Username { get; set; }
            public string Email { get; set; }
            public string FullName { get; set; }
            public List<string> Roles { get; set; }
            public List<string> Permissions { get; set; }
            public DateTime? LastLogin { get; set; }
            public bool MfaEnabled { get; set; }
        }

        public class MfaVerificationRequest
        {
            public string Code { get; set; }
        }

        public class DisableMfaRequest
        {
            public string Password { get; set; }
        }

        public class RefreshTokenRequest
        {
            public string RefreshToken { get; set; }
        }

        public class ChangePasswordRequest
        {
            public string CurrentPassword { get; set; }
            public string NewPassword { get; set; }
        }

        public class ForgotPasswordRequest
        {
            public string Email { get; set; }
        }

        public class ResetPasswordRequest
        {
            public string Token { get; set; }
            public string NewPassword { get; set; }
        }

        public class ValidateTokenRequest
        {
            public string Token { get; set; }
        }

        #endregion
    }
}