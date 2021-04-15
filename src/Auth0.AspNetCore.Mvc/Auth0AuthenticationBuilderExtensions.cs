using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;

namespace Auth0.AspNetCore.Mvc
{
    public static class Auth0AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddAuth0MVC(this AuthenticationBuilder builder, Action<Auth0Options> configureOptions)
        {
            var auth0Options = new Auth0Options();

            configureOptions(auth0Options);

            builder.AddCookie();
            builder.AddOpenIdConnect(Constants.AuthenticationScheme, options => ConfigureOpenIdConnect(options, auth0Options));

            return builder;
        }

        private static void ConfigureOpenIdConnect(OpenIdConnectOptions oidcOptions, Auth0Options auth0Options)
        {
            oidcOptions.Authority = $"https://{auth0Options.Domain}";
            oidcOptions.ClientId = auth0Options.ClientId;
            oidcOptions.ClientSecret = auth0Options.ClientSecret;
            oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
            oidcOptions.Scope.Clear();
            oidcOptions.Scope.Add("openid");
            oidcOptions.Scope.Add("profile");
            oidcOptions.Scope.Add("email");
            oidcOptions.CallbackPath = new PathString(Constants.DefaultCallbackPath);
            oidcOptions.ClaimsIssuer = Constants.ClaimsIssuer;

            oidcOptions.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name"
            };
        }
    }
}
