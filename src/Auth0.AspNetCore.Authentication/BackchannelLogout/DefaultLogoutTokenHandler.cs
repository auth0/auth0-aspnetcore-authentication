using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    public class DefaultLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IMemoryCache memoryCache;
        private readonly ILogger logger;

        public DefaultLogoutTokenHandler(IMemoryCache memoryCache, ILoggerFactory loggerFactory)
        {
            this.memoryCache = memoryCache;
            this.logger = loggerFactory.CreateLogger("Auth0.DefaultLogoutTokenHandler");
        }

        public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken)
        {
            this.logger.LogWarning("Using back-channel logout without providing a custom ILogoutTokenHandler implementation, falling back to `DefaultLogoutTokenHandler. Be aware this store the tokens in IMemoryCache`");

            // TODO: Configure expiration
            memoryCache.Set($"{issuer}|{sid}", logoutToken);

            return Task.CompletedTask;
        }

        public Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            this.logger.LogWarning("Using back-channel logout without providing a custom ILogoutTokenHandler implementation, falling back to `DefaultLogoutTokenHandler. Be aware this store the tokens in IMemoryCache`");

            var token = memoryCache.Get($"{issuer}|{sid}");
            return Task.FromResult(token != null);
        }

        public Task RemoveAsync(string issuer, string sid)
        {
            this.logger.LogWarning("Using back-channel logout without providing a custom ILogoutTokenHandler implementation, falling back to `DefaultLogoutTokenHandler. Be aware this store the tokens in IMemoryCache`");

            memoryCache.Remove($"{issuer}|{sid}");
            return Task.CompletedTask;
        }
    }
}
