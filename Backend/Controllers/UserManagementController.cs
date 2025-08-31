

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SabaFone.Backend.Services;
using SabaFone.Backend.Data.Users.Models;
using SabaFone.Backend.Utils;

namespace SabaFone.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin,UserManager")]
    public class UserManagementController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;
        private readonly IAuditService _auditService;
        private readonly INotificationService _notificationService;
        private readonly ILogger<UserManagementController> _logger;

        public UserManagementController(
            IUserService userService,
            IRoleService roleService,
            IAuditService auditService,
            INotificationService notificationService,
            ILogger<UserManagementController> logger)
        {
            _userService = userService;
            _roleService = roleService;
            _auditService = auditService;
            _notificationService = notificationService;
            _logger = logger;
        }

        /// <summary>
        /// Gets all users
        /// </summary>
        [HttpGet("users")]
        public async Task<IActionResult> GetUsers(
            [FromQuery] string search = null,
            [FromQuery] string role = null,
            [FromQuery] bool? isActive = null,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 50)
        {
            try
            {
                var users = await _userService.GetUsersAsync(search, role, isActive, page, pageSize);
                
                var response = users.Select(u => new UserDto
                {
                    UserId = u.UserId,
                    Username = u.Username,
                    Email = u.Email,
                    FullName = u.FullName,
                    IsActive = u.IsActive,
                    IsLocked = u.IsLocked,
                    CreatedAt = u.CreatedAt,
                    LastLogin = u.LastLogin,
                    Roles = u.UserRoles?.Select(ur => ur.Role.Name).ToList()
                });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting users");
                return StatusCode(500, new { message = "An error occurred while getting users" });
            }
        }

        /// <summary>
        /// Gets user by ID
        /// </summary>
        [HttpGet("users/{userId}")]
        public async Task<IActionResult> GetUser(Guid userId)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                return Ok(new UserDetailDto
                {
                    UserId = user.UserId,
                    Username = user.Username,
                    Email = user.Email,
                    FullName = user.FullName,
                    PhoneNumber = user.PhoneNumber,
                    Department = user.Department,
                    IsActive = user.IsActive,
                    IsLocked = user.IsLocked,
                    MfaEnabled = user.MfaEnabled,
                    CreatedAt = user.CreatedAt,
                    LastLogin = user.LastLogin,
                    PasswordExpiresAt = user.PasswordExpiresAt,
                    Roles = user.UserRoles?.Select(ur => new RoleDto
                    {
                        RoleId = ur.Role.RoleId,
                        Name = ur.Role.Name,
                        Description = ur.Role.Description
                    }).ToList(),
                    Permissions = await _userService.GetUserPermissionsAsync(userId)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting user {userId}");
                return StatusCode(500, new { message = "An error occurred while getting user" });
            }
        }

        /// <summary>
        /// Creates new user
        /// </summary>
        [HttpPost("users")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            try
            {
                // Validate email
                if (!request.Email.IsValidEmail())
                {
                    return BadRequest(new { message = "Invalid email format" });
                }

                // Check if user exists
                var existingUser = await _userService.GetUserByUsernameAsync(request.Username);
                if (existingUser != null)
                {
                    return Conflict(new { message = "Username already exists" });
                }

                existingUser = await _userService.GetUserByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return Conflict(new { message = "Email already exists" });
                }

                // Generate temporary password
                var tempPassword = CryptoHelper.GenerateRandomString(12, true);
                
                // Create user
                var user = new User
                {
                    Username = request.Username,
                    Email = request.Email,
                    FullName = request.FullName,
                    PhoneNumber = request.PhoneNumber,
                    Department = request.Department,
                    PasswordHash = CryptoHelper.HashPassword(tempPassword),
                    MustChangePassword = true,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    PasswordExpiresAt = DateTime.UtcNow.AddDays(90)
                };

                var createdUser = await _userService.CreateUserAsync(user);

                // Assign roles
                if (request.RoleIds?.Any() == true)
                {
                    foreach (var roleId in request.RoleIds)
                    {
                        await _roleService.AssignRoleToUserAsync(createdUser.UserId, roleId);
                    }
                }

                // Send welcome email with temporary password
                await _notificationService.SendNotificationAsync(
                    createdUser.UserId,
                    "Welcome to SSAS",
                    $"Your account has been created. Username: {user.Username}, Temporary Password: {tempPassword}",
                    "info");

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "USER_CREATED",
                    $"User {user.Username} created",
                    currentUserId);

                return CreatedAtAction(nameof(GetUser), new { userId = createdUser.UserId }, 
                    new { userId = createdUser.UserId, message = "User created successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user");
                return StatusCode(500, new { message = "An error occurred while creating user" });
            }
        }

        /// <summary>
        /// Updates user
        /// </summary>
        [HttpPut("users/{userId}")]
        public async Task<IActionResult> UpdateUser(Guid userId, [FromBody] UpdateUserRequest request)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                // Update user properties
                user.FullName = request.FullName ?? user.FullName;
                user.Email = request.Email ?? user.Email;
                user.PhoneNumber = request.PhoneNumber ?? user.PhoneNumber;
                user.Department = request.Department ?? user.Department;
                user.UpdatedAt = DateTime.UtcNow;

                await _userService.UpdateUserAsync(user);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "USER_UPDATED",
                    $"User {user.Username} updated",
                    currentUserId);

                return Ok(new { message = "User updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating user {userId}");
                return StatusCode(500, new { message = "An error occurred while updating user" });
            }
        }

        /// <summary>
        /// Deletes user
        /// </summary>
        [HttpDelete("users/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(Guid userId)
        {
            try
            {
                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                
                if (userId == currentUserId)
                {
                    return BadRequest(new { message = "Cannot delete your own account" });
                }

                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                await _userService.DeleteUserAsync(userId);

                await _auditService.LogAsync(
                    "USER_DELETED",
                    $"User {user.Username} deleted",
                    currentUserId);

                return Ok(new { message = "User deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting user {userId}");
                return StatusCode(500, new { message = "An error occurred while deleting user" });
            }
        }

        /// <summary>
        /// Activates/Deactivates user
        /// </summary>
        [HttpPut("users/{userId}/status")]
        public async Task<IActionResult> UpdateUserStatus(Guid userId, [FromBody] UpdateStatusRequest request)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                user.IsActive = request.IsActive;
                user.UpdatedAt = DateTime.UtcNow;

                await _userService.UpdateUserAsync(user);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                var action = request.IsActive ? "activated" : "deactivated";
                
                await _auditService.LogAsync(
                    $"USER_{action.ToUpper()}",
                    $"User {user.Username} {action}",
                    currentUserId);

                await _notificationService.SendNotificationAsync(
                    userId,
                    "Account Status Changed",
                    $"Your account has been {action}",
                    "warning");

                return Ok(new { message = $"User {action} successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating user status {userId}");
                return StatusCode(500, new { message = "An error occurred while updating status" });
            }
        }

        /// <summary>
        /// Locks/Unlocks user account
        /// </summary>
        [HttpPut("users/{userId}/lock")]
        public async Task<IActionResult> UpdateUserLockStatus(Guid userId, [FromBody] UpdateLockRequest request)
        {
            try
            {
                var result = request.IsLocked
                    ? await _userService.LockUserAsync(userId, request.Reason)
                    : await _userService.UnlockUserAsync(userId);

                if (!result)
                {
                    return NotFound(new { message = "User not found" });
                }

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                var action = request.IsLocked ? "locked" : "unlocked";
                
                await _auditService.LogAsync(
                    $"USER_{action.ToUpper()}",
                    $"User account {action}. Reason: {request.Reason}",
                    currentUserId);

                return Ok(new { message = $"User account {action} successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating lock status for user {userId}");
                return StatusCode(500, new { message = "An error occurred while updating lock status" });
            }
        }

        /// <summary>
        /// Resets user password
        /// </summary>
        [HttpPost("users/{userId}/reset-password")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ResetUserPassword(Guid userId)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(userId);
                if (user == null)
                {
                    return NotFound(new { message = "User not found" });
                }

                // Generate new temporary password
                var tempPassword = CryptoHelper.GenerateRandomString(12, true);
                
                user.PasswordHash = CryptoHelper.HashPassword(tempPassword);
                user.MustChangePassword = true;
                user.PasswordResetAt = DateTime.UtcNow;
                user.UpdatedAt = DateTime.UtcNow;

                await _userService.UpdateUserAsync(user);

                // Send password reset notification
                await _notificationService.SendNotificationAsync(
                    userId,
                    "Password Reset",
                    $"Your password has been reset. New temporary password: {tempPassword}",
                    "warning");

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "USER_PASSWORD_RESET",
                    $"Password reset for user {user.Username}",
                    currentUserId);

                return Ok(new { message = "Password reset successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error resetting password for user {userId}");
                return StatusCode(500, new { message = "An error occurred while resetting password" });
            }
        }

        /// <summary>
        /// Gets all roles
        /// </summary>
        [HttpGet("roles")]
        public async Task<IActionResult> GetRoles()
        {
            try
            {
                var roles = await _roleService.GetRolesAsync();
                
                var response = roles.Select(r => new RoleDto
                {
                    RoleId = r.RoleId,
                    Name = r.Name,
                    Description = r.Description,
                    IsSystem = r.IsSystem,
                    UserCount = r.UserRoles?.Count ?? 0
                });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting roles");
                return StatusCode(500, new { message = "An error occurred while getting roles" });
            }
        }

        /// <summary>
        /// Creates new role
        /// </summary>
        [HttpPost("roles")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            try
            {
                var role = new Role
                {
                    Name = request.Name,
                    Description = request.Description,
                    IsSystem = false,
                    CreatedAt = DateTime.UtcNow
                };

                var createdRole = await _roleService.CreateRoleAsync(role);

                // Assign permissions
                if (request.PermissionIds?.Any() == true)
                {
                    foreach (var permissionId in request.PermissionIds)
                    {
                        await _roleService.AssignPermissionToRoleAsync(createdRole.RoleId, permissionId);
                    }
                }

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "ROLE_CREATED",
                    $"Role {role.Name} created",
                    currentUserId);

                return Ok(new { roleId = createdRole.RoleId, message = "Role created successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating role");
                return StatusCode(500, new { message = "An error occurred while creating role" });
            }
        }

        /// <summary>
        /// Updates role
        /// </summary>
        [HttpPut("roles/{roleId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateRole(Guid roleId, [FromBody] UpdateRoleRequest request)
        {
            try
            {
                var role = await _roleService.GetRoleByIdAsync(roleId);
                if (role == null)
                {
                    return NotFound(new { message = "Role not found" });
                }

                if (role.IsSystem)
                {
                    return BadRequest(new { message = "Cannot modify system role" });
                }

                role.Name = request.Name ?? role.Name;
                role.Description = request.Description ?? role.Description;
                role.UpdatedAt = DateTime.UtcNow;

                await _roleService.UpdateRoleAsync(role);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "ROLE_UPDATED",
                    $"Role {role.Name} updated",
                    currentUserId);

                return Ok(new { message = "Role updated successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating role {roleId}");
                return StatusCode(500, new { message = "An error occurred while updating role" });
            }
        }

        /// <summary>
        /// Deletes role
        /// </summary>
        [HttpDelete("roles/{roleId}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteRole(Guid roleId)
        {
            try
            {
                var role = await _roleService.GetRoleByIdAsync(roleId);
                if (role == null)
                {
                    return NotFound(new { message = "Role not found" });
                }

                if (role.IsSystem)
                {
                    return BadRequest(new { message = "Cannot delete system role" });
                }

                await _roleService.DeleteRoleAsync(roleId);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "ROLE_DELETED",
                    $"Role {role.Name} deleted",
                    currentUserId);

                return Ok(new { message = "Role deleted successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting role {roleId}");
                return StatusCode(500, new { message = "An error occurred while deleting role" });
            }
        }

        /// <summary>
        /// Assigns role to user
        /// </summary>
        [HttpPost("users/{userId}/roles")]
        public async Task<IActionResult> AssignRoleToUser(Guid userId, [FromBody] AssignRoleRequest request)
        {
            try
            {
                await _roleService.AssignRoleToUserAsync(userId, request.RoleId);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "ROLE_ASSIGNED",
                    $"Role {request.RoleId} assigned to user {userId}",
                    currentUserId);

                return Ok(new { message = "Role assigned successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error assigning role to user {userId}");
                return StatusCode(500, new { message = "An error occurred while assigning role" });
            }
        }

        /// <summary>
        /// Removes role from user
        /// </summary>
        [HttpDelete("users/{userId}/roles/{roleId}")]
        public async Task<IActionResult> RemoveRoleFromUser(Guid userId, Guid roleId)
        {
            try
            {
                await _roleService.RemoveRoleFromUserAsync(userId, roleId);

                var currentUserId = Guid.Parse(User.FindFirst("UserId")?.Value);
                await _auditService.LogAsync(
                    "ROLE_REMOVED",
                    $"Role {roleId} removed from user {userId}",
                    currentUserId);

                return Ok(new { message = "Role removed successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error removing role from user {userId}");
                return StatusCode(500, new { message = "An error occurred while removing role" });
            }
        }

        /// <summary>
        /// Gets user activity logs
        /// </summary>
        [HttpGet("users/{userId}/activity")]
        public async Task<IActionResult> GetUserActivity(Guid userId, [FromQuery] int days = 7)
        {
            try
            {
                var activity = await _userService.GetUserActivityAsync(userId, days);
                return Ok(activity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting activity for user {userId}");
                return StatusCode(500, new { message = "An error occurred while getting activity" });
            }
        }

        #region DTOs and Request Models

        public class UserDto
        {
            public Guid UserId { get; set; }
            public string Username { get; set; }
            public string Email { get; set; }
            public string FullName { get; set; }
            public bool IsActive { get; set; }
            public bool IsLocked { get; set; }
            public DateTime CreatedAt { get; set; }
            public DateTime? LastLogin { get; set; }
            public List<string> Roles { get; set; }
        }

        public class UserDetailDto : UserDto
        {
            public string PhoneNumber { get; set; }
            public string Department { get; set; }
            public bool MfaEnabled { get; set; }
            public DateTime? PasswordExpiresAt { get; set; }
           // public List<RoleDto> Roles { get; set; }
            public new List<RoleDto> Roles { get; set; }
            public List<string> Permissions { get; set; }
        }

        public class RoleDto
        {
            public Guid RoleId { get; set; }
            public string Name { get; set; }
            public string Description { get; set; }
            public bool IsSystem { get; set; }
            public int UserCount { get; set; }
        }

        public class CreateUserRequest
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string FullName { get; set; }
            public string PhoneNumber { get; set; }
            public string Department { get; set; }
            public List<Guid> RoleIds { get; set; }
        }

        public class UpdateUserRequest
        {
            public string FullName { get; set; }
            public string Email { get; set; }
            public string PhoneNumber { get; set; }
            public string Department { get; set; }
        }

        public class UpdateStatusRequest
        {
            public bool IsActive { get; set; }
        }

        public class UpdateLockRequest
        {
            public bool IsLocked { get; set; }
            public string Reason { get; set; }
        }

        public class CreateRoleRequest
        {
            public string Name { get; set; }
            public string Description { get; set; }
            public List<Guid> PermissionIds { get; set; }
        }

        public class UpdateRoleRequest
        {
            public string Name { get; set; }
            public string Description { get; set; }
        }

        public class AssignRoleRequest
        {
            public Guid RoleId { get; set; }
        }

        #endregion
    }
}