using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication
{
    public class BackchannelLogoutHandler
    {
        public virtual async Task HandleRequestAsync(HttpContext context)
        {
            try
            {
                if (context.Request.Method == "POST")
                {
                    if (context.Request.HasFormContentType)
                    {
                        var logoutToken = context.Request.Form["logout_token"].FirstOrDefault();

                        if (!String.IsNullOrWhiteSpace(logoutToken))
                        {
                            var auth0Options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(Auth0Constants.AuthenticationScheme);
                            var oidcOptions = context.RequestServices.GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>().Get(Auth0Constants.AuthenticationScheme);

                            var principal = await ValidateLogoutToken(logoutToken, oidcOptions, context);

                            if (principal != null)
                            {
                                var issuer = principal.Claims.FirstOrDefault(c => c.Type == "iss")?.Value;
                                var sid = principal.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;

                                LogoutTokenStore.Instance.Set($"{issuer}|{sid}", logoutToken);

                                return;
                            }
                        }
                        else
                        {
                            await context.WriteErrorAsync(400, "invalid_request", "Missing logout_token");
                        }
                    }
                }
                else
                {
                    // 405: Method Not Allowed
                    context.Response.StatusCode = 405;
                }
            }
            catch (Exception ex)
            {
                await context.WriteErrorAsync(400, "invalid_request", ex.Message);
            }

        }

        private async Task<ClaimsPrincipal> ValidateLogoutToken(String token, OpenIdConnectOptions oidcOptions, HttpContext context)
        {
            OpenIdConnectConfiguration? configuration = null;

            if (oidcOptions.ConfigurationManager != null)
            {
                configuration = await oidcOptions.ConfigurationManager.GetConfigurationAsync(context.RequestAborted);
            }

            if (configuration != null)
            {
                var issuer = new[] { configuration.Issuer };
                oidcOptions.TokenValidationParameters.ValidIssuers = oidcOptions.TokenValidationParameters.ValidIssuers?.Concat(issuer) ?? issuer;

                oidcOptions.TokenValidationParameters.IssuerSigningKeys = oidcOptions.TokenValidationParameters.IssuerSigningKeys?.Concat(configuration.SigningKeys)
                    ?? configuration.SigningKeys;
            }

            return oidcOptions.SecurityTokenValidator.ValidateToken(token, oidcOptions.TokenValidationParameters, out SecurityToken validatedToken);

        }

    }

    public static class HttpContextExtensions
    {

        public static async Task WriteErrorAsync(this HttpContext context, int statusCode, string error, string description)
        {
            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsJsonAsync(new { error = error, error_description = description });
        }
    }
}

