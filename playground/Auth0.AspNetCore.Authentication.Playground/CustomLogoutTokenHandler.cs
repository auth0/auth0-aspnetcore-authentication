using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication.Playground
{
    public class CustomLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IMemoryCache memoryCache;

        public CustomLogoutTokenHandler(IMemoryCache memoryCache)
        {
            this.memoryCache = memoryCache;
        }

        public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken)
        {
            // TODO: Configure expiration
            memoryCache.Set($"{issuer}|{sid}", logoutToken);

            return Task.CompletedTask;
        }

        public Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            var token = memoryCache.Get($"{issuer}|{sid}");
            return Task.FromResult(token != null);
        }

        public Task RemoveAsync(string issuer, string sid)
        {
            memoryCache.Remove($"{issuer}|{sid}");
            return Task.CompletedTask;
        }
    }

}
