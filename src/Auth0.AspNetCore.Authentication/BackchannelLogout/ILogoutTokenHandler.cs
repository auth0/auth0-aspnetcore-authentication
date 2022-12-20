using Microsoft.Extensions.Caching.Memory;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{

    public interface ILogoutTokenHandler
    {
        Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken);
        Task<bool> IsLoggedOutAsync(string issuer, string sid);
        // TODO: REMOVE! Only for testing!
        Task RemoveAsync(string issuer, string sid);
    }
}
