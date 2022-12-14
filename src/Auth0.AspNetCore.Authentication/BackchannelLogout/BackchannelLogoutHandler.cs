using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication
{
    public class BackchannelLogoutHandler
    {
        private readonly ILogoutTokenHandler tokenHandler;

        public BackchannelLogoutHandler(ILogoutTokenHandler tokenHandler)
        {
            this.tokenHandler = tokenHandler;
        }
        public virtual async Task HandleRequestAsync(HttpContext context)
        {
            try
            {
                context.Response.Headers.Add("Cache-Control", "no-cache, no-store");

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

                            await tokenHandler.OnTokenReceivedAsync(issuer, sid, logoutToken);

                            return;
                        }
                    }
                    else
                    {
                        await context.WriteErrorAsync(400, "invalid_request", "Missing logout_token");
                    }
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

