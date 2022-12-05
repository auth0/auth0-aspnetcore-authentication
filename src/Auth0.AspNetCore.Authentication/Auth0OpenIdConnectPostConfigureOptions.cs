using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Used to setup Auth0 specific defaults for <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectoptions">OpenIdConnectOptions</see>.
    /// </summary>
    internal class Auth0OpenIdConnectPostConfigureOptions : IPostConfigureOptions<OpenIdConnectOptions>
    {
        public void PostConfigure(string name, OpenIdConnectOptions options)
        {
            options.Backchannel.DefaultRequestHeaders.Add("Auth0-Client", Utils.CreateAgentString());
        }
    }

    internal class Auth0CookieAuthenticationPostConfigureOptions : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        public void PostConfigure(string name, CookieAuthenticationOptions options)
        {
            options.SessionStore = new Auth0TicketStoreDecorator(options.SessionStore!);
        }
    }

    internal class Auth0TicketStoreDecorator: ITicketStore
    {
        private readonly ITicketStore ticketStore;
        private readonly IDictionary<string, string> sidMap = new Dictionary<string, string>();

        public Auth0TicketStoreDecorator(ITicketStore ticketStore)
        {
            this.ticketStore = ticketStore;
        }

        public Task RemoveAsync(string key)
        {
            var sid = sidMap.ToList().SingleOrDefault(i => i.Value == key).Key;
            sidMap.Remove(sid);

            return ticketStore.RemoveAsync(key);
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            return ticketStore.RenewAsync(key, ticket);
        }

        public Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            return ticketStore.RetrieveAsync(key);
        }

        public async Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            var sid = ticket.Principal.FindFirst("sid")!.Value;
            var id = await ticketStore.StoreAsync(ticket);

            sidMap.Add(sid, id);
            return id;
        }
    }

    public class Auth0TicketStore2 : ITicketStore
    {

        private IDictionary<string, AuthenticationTicket> _cache = new Dictionary<string, AuthenticationTicket>();

        public Task RemoveAsync(string key)
        {
            _cache.Remove(key);
            return Task.CompletedTask;
        }

        public Task RenewAsync(string key, AuthenticationTicket ticket)
        {
            if (_cache.ContainsKey(key))
            {
                _cache[key] = ticket;
            }
            else
            {
                _cache.Add(key, ticket);
            }
            return Task.CompletedTask;
        }

        public Task<AuthenticationTicket> RetrieveAsync(string key)
        {
            return Task.FromResult(_cache[key]);
        }

        public async Task<string> StoreAsync(AuthenticationTicket ticket)
        {
            var id = Guid.NewGuid();
            var key = "Auth0." + id;
            await RenewAsync(key, ticket);
            return key;
        }
    }
}
