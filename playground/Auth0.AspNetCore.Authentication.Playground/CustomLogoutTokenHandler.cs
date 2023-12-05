using System;
using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;

namespace Auth0.AspNetCore.Authentication.Playground
{
    public class CustomLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IMemoryCache _memoryCache;

        public CustomLogoutTokenHandler(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
        }

        public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
        {
            _memoryCache.Set($"{issuer}|{sid}", logoutToken, expiration);

            return Task.CompletedTask;
        }

        public Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            var token = _memoryCache.Get($"{issuer}|{sid}");
            return Task.FromResult(token != null);
        }
    }

}
