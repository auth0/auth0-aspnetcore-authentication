using System;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout
{
    public interface ILogoutTokenHandler
    {
        Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration);
        Task<bool> IsLoggedOutAsync(string issuer, string sid);
    }
}
