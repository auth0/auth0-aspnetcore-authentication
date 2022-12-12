using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Caching.Distributed;
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
}
