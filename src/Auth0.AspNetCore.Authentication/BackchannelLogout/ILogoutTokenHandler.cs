using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    public class DefaultLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IMemoryCache memoryCache;

        public DefaultLogoutTokenHandler(IMemoryCache memoryCache)
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

    public interface ILogoutTokenHandler
    {
        Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken);
        Task<bool> IsLoggedOutAsync(string issuer, string sid);
        // TODO: REMOVE! Only for testing!
        Task RemoveAsync(string issuer, string sid);
    }
}
