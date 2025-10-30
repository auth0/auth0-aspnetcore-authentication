using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout
{
    public class BackchannelLogoutHandler
    {
        private readonly ILogoutTokenHandler _tokenHandler;
        private readonly string _authenticationScheme;

        public BackchannelLogoutHandler(ILogoutTokenHandler tokenHandler) 
            : this(tokenHandler, Auth0Constants.AuthenticationScheme)
        {
        }

        public BackchannelLogoutHandler(ILogoutTokenHandler tokenHandler, string authenticationScheme)
        {
            _tokenHandler = tokenHandler;
            _authenticationScheme = authenticationScheme;
        }

        public async Task HandleRequestAsync(HttpContext context)
        {
            try
            {
                context.Response.Headers.Add("Cache-Control", "no-cache, no-store");

                if (context.Request.HasFormContentType)
                {
                    var logoutToken = context.Request.Form["logout_token"].FirstOrDefault();

                    if (!String.IsNullOrWhiteSpace(logoutToken))
                    {
                        var auth0Options = context.RequestServices
                            .GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>()
                            .Get(_authenticationScheme);
                        var oidcOptions = context.RequestServices
                            .GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>()
                            .Get(_authenticationScheme);

                        var principal = await ValidateLogoutToken(logoutToken, oidcOptions, context);

                        if (principal != null)
                        {
                            var issuer = principal.Claims.First(c => c.Type == "iss").Value;
                            var sid = principal.Claims.First(c => c.Type == "sid").Value;

                            var cookieOptions = context.RequestServices
                                .GetRequiredService<IOptionsSnapshot<CookieAuthenticationOptions>>()
                                .Get(auth0Options.CookieAuthenticationScheme);

                            await _tokenHandler.OnTokenReceivedAsync(issuer, sid, logoutToken,
                                cookieOptions.ExpireTimeSpan);
                        }
                    }
                    else
                    {
                        await context.WriteErrorAsync(400, "invalid_request", "Missing logout_token.");
                    }
                }
                else
                {
                    await context.WriteErrorAsync(400, "invalid_request",
                        "Only application/x-www-form-urlencoded is allowed.");
                }
            }
            catch (LogoutTokenValidationException ex)
            {
                await context.WriteErrorAsync(400, "invalid_request", ex.Message);
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

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidIssuer = oidcOptions.TokenValidationParameters.ValidIssuer,
                ValidAudience = oidcOptions.TokenValidationParameters.ValidAudience,
            };

            if (configuration != null)
            {
                tokenValidationParameters.IssuerSigningKeys =
                    oidcOptions.TokenValidationParameters.IssuerSigningKeys?.Concat(configuration.SigningKeys)
                    ?? configuration.SigningKeys;
            }

            var principal =
                oidcOptions.SecurityTokenValidator.ValidateToken(token, tokenValidationParameters, out SecurityToken _);

            LogoutTokenValidator.Validate(new JwtSecurityTokenHandler().ReadJwtToken(token));

            return principal;
        }
    }

    public static class HttpContextExtensions
    {
        public static async Task WriteErrorAsync(this HttpContext context, int statusCode, string error, string description)
        {
            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsJsonAsync(new { error, error_description = description });
        }

        public static async Task WriteStatusCodeAsync(this HttpContext context, int statusCode)
        {
            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsync(string.Empty);
        }
    }
}