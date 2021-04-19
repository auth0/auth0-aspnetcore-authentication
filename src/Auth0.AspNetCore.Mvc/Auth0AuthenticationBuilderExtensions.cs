using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    public static class Auth0AuthenticationBuilderExtensions
    {
        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="builder">The original <see cref="AuthenticationBuilder"/> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0Options"/></param>
        /// <returns>The <see cref="AuthenticationBuilder"/ instance that has been configured.</returns>
        public static AuthenticationBuilder AddAuth0Mvc(this AuthenticationBuilder builder, Action<Auth0Options> configureOptions)
        {
            var auth0Options = new Auth0Options();

            configureOptions(auth0Options);

            builder.AddCookie();
            builder.AddOpenIdConnect(Constants.AuthenticationScheme, options => ConfigureOpenIdConnect(options, auth0Options));

            return builder;
        }

        /// <summary>
        /// Configure Open ID Connect based on the provided <see cref="Auth0Options"/>.
        /// </summary>
        /// <param name="oidcOptions">A reference to the <see cref="OpenIdConnectOptions"/> that needs to be configured./param>
        /// <param name="auth0Options">The provided <see cref="Auth0Options"/>.</param>
        private static void ConfigureOpenIdConnect(OpenIdConnectOptions oidcOptions, Auth0Options auth0Options)
        {
            oidcOptions.Authority = $"https://{auth0Options.Domain}";
            oidcOptions.ClientId = auth0Options.ClientId;
            oidcOptions.ClientSecret = auth0Options.ClientSecret;
            oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
            oidcOptions.Scope.Clear();
            oidcOptions.Scope.AddRange(auth0Options.Scope.Split(" "));
            oidcOptions.CallbackPath = new PathString(auth0Options.CallbackPath ?? Constants.DefaultCallbackPath);
            oidcOptions.ClaimsIssuer = Constants.ClaimsIssuer;

            oidcOptions.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name"
            };

            oidcOptions.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = CreateOnRedirectToIdentityProvider(auth0Options),
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(Auth0Options auth0Options)
        {
            return (context) =>
            {
                foreach (var extraParam in GetAuthorizeParameters(context.Properties.Items))
                {
                    context.ProtocolMessage.SetParameter(extraParam.Key, extraParam.Value);
                }

                return Task.CompletedTask;
            };
        }

        private static IDictionary<string, string> GetAuthorizeParameters(IDictionary<string, string> authSessionItems)
        {
            var parameters = new Dictionary<string, string>();
            var authorizeParameters = new List<string> { "scope" };

            foreach (var key in authorizeParameters)
            {
                if (authSessionItems.ContainsKey(key))
                    parameters[key] = authSessionItems[key];
            }

            return parameters;
        }
    }
}
