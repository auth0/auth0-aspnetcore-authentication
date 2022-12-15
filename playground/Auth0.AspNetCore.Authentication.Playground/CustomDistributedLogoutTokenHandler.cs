using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System.Text;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication.Playground
{
    public class CustomDistributedLogoutTokenHandler : ILogoutTokenHandler
    {
        private readonly IDistributedCache cache;

        public CustomDistributedLogoutTokenHandler(IDistributedCache cache)
        {
            this.cache = cache;
        }

        public async Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken)
        {
            // TODO: Configure expiration
            await cache.SetAsync($"{issuer}|{sid}", Encoding.ASCII.GetBytes(logoutToken));
        }

        public async Task<bool> IsLoggedOutAsync(string issuer, string sid)
        {
            var token = await cache.GetAsync($"{issuer}|{sid}");
            return token != null;
        }

        public async Task RemoveAsync(string issuer, string sid)
        {
            await cache.RemoveAsync($"{issuer}|{sid}");
        }
    }

}
