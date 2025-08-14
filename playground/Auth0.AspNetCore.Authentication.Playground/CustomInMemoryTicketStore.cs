using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using System.Linq;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication.Playground;

public class CustomInMemoryTicketStore : ITicketStore
{
    private readonly IMemoryCache _cache;

    public CustomInMemoryTicketStore(IMemoryCache cache)
    {
        _cache = cache;
    }

    public Task RemoveAsync(string key)
    {
        _cache.Remove(key);

        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket> RetrieveAsync(string key)
    {
        var ticket = _cache.Get<AuthenticationTicket>(key);

        return Task.FromResult(ticket);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _cache.Set(key, ticket);

        return Task.CompletedTask;
    }

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = ticket.Principal.Claims
            .First(c => c.Type == "sid").Value;

        _cache.Set(key, ticket);

        return Task.FromResult(key);
    }
}