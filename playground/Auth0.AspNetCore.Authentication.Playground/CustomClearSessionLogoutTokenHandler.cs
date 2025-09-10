using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;

namespace Auth0.AspNetCore.Authentication.Playground;

public class CustomClearSessionLogoutTokenHandler : ILogoutTokenHandler
{
    private readonly ITicketStore store;

    public CustomClearSessionLogoutTokenHandler(ITicketStore store)
    {
        this.store = store;
    }

    public async Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
    {
        await store.RemoveAsync(sid);
    }

    public Task<bool> IsLoggedOutAsync(string issuer, string sid)
    {
        return Task.FromResult(false);
    }
}