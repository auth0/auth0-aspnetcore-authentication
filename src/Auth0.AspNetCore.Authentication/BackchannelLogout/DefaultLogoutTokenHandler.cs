using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout
{
    public class DefaultLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger _logger;

        public DefaultLogoutTokenHandler(IMemoryCache memoryCache, ILoggerFactory loggerFactory)
        {
            _memoryCache = memoryCache;
            _logger = loggerFactory.CreateLogger("Auth0.DefaultLogoutTokenHandler");
        }

        public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
        {
            _logger.LogWarning("Using back-channel logout without providing a custom ILogoutTokenHandler implementation, falling back to `DefaultLogoutTokenHandler. Be aware this store the tokens in IMemoryCache`");
            
            _memoryCache.Set($"{issuer}|{sid}", logoutToken, expiration);

            return Task.CompletedTask;
        }

        public Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            _logger.LogWarning("Using back-channel logout without providing a custom ILogoutTokenHandler implementation, falling back to `DefaultLogoutTokenHandler. Be aware this store the tokens in IMemoryCache`");

            var token = _memoryCache.Get($"{issuer}|{sid}");            
            return Task.FromResult(token != null);
        }
    }
}
