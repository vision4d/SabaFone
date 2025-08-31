using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using System;
using System.Threading.Tasks;
using SabaFone.Backend.Exceptions;
namespace SabaFone.Backend.Hubs
{
    [Authorize(Roles = "Admin,SecurityOfficer")]
    public class SecurityHub : Hub
    {
        public async Task BroadcastSecurityAlert(string severity, string message)
        {
            await Clients.All.SendAsync("SecurityAlert", severity, message);
        }
        
        public async Task JoinSecurityGroup()
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, "SecurityTeam");
        }
        
        public async Task LeaveSecurityGroup()
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, "SecurityTeam");
        }
    }
}