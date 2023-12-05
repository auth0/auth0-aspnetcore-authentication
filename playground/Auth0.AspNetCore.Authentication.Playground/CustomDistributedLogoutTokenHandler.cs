using System;
using Microsoft.Extensions.Caching.Distributed;
using System.Text;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;

namespace Auth0.AspNetCore.Authentication.Playground
{
    public class CustomDistributedLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IDistributedCache _cache;

        public CustomDistributedLogoutTokenHandler(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
        {
            await _cache.SetAsync($"{issuer}|{sid}", Encoding.ASCII.GetBytes(logoutToken), new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = expiration
            });
        }

        public async Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            var token = await _cache.GetAsync($"{issuer}|{sid}");
            return token != null;
        }
    }

}
