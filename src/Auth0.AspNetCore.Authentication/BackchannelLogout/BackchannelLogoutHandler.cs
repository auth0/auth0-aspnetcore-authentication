using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
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

                        var customDomainsOptions = context.RequestServices
                            .GetService<IOptionsMonitor<Auth0CustomDomainsOptions>>()
                            ?.Get(_authenticationScheme);
                        var isMcdEnabled = customDomainsOptions?.IsMultipleCustomDomainsEnabled == true;

                        if (isMcdEnabled)
                        {
                            ValidateIssuerMatchesResolvedDomain(logoutToken, context);
                        }

                        var principal = await ValidateLogoutToken(logoutToken, oidcOptions, context, isMcdEnabled);

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

        /// <summary>
        /// When MCD is enabled, extracts the issuer from the unverified token and validates it matches
        /// the domain resolved for the current request. This check happens BEFORE full JWT
        /// validation so we avoid fetching JWKS for tokens from the wrong tenant.
        /// </summary>
        private static void ValidateIssuerMatchesResolvedDomain(string token, HttpContext context)
        {
            var unverifiedIssuer = ExtractUnverifiedIssuer(token);

            var resolvedDomain = context.GetResolvedDomain();

            if (string.IsNullOrWhiteSpace(resolvedDomain))
            {
                throw new LogoutTokenValidationException(
                    "Unable to resolve domain for this request. Ensure DomainResolver is configured.");
            }

            var normalizedIssuer = Utils.ToAuthority(unverifiedIssuer);
            var normalizedResolved = Utils.ToAuthority(resolvedDomain);

            if (!string.Equals(normalizedIssuer, normalizedResolved))
            {
                throw new LogoutTokenValidationException("Logout token issuer does not match the resolved domain.");
            }
        }

        /// <summary>
        /// Reads the JWT without signature validation to extract the issuer claim.
        /// Throws <see cref="LogoutTokenValidationException"/> if the token is malformed.
        /// Note: This does not validate the signature or any other JWT claims.
        /// </summary>
        private static string ExtractUnverifiedIssuer(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
                throw new LogoutTokenValidationException("Logout token is malformed or not a valid JWT.");
            return handler.ReadJwtToken(token).Issuer;
        }

        private async Task<ClaimsPrincipal> ValidateLogoutToken(string token, OpenIdConnectOptions oidcOptions, HttpContext context, bool isMcdEnabled)
        {
            OpenIdConnectConfiguration? configuration = null;

            if (oidcOptions.ConfigurationManager != null)
            {
                configuration = await oidcOptions.ConfigurationManager.GetConfigurationAsync(context.RequestAborted);
            }

            var validIssuer = isMcdEnabled
                ? Utils.ToAuthority(context.GetResolvedDomain()
                    ?? throw new LogoutTokenValidationException(
                        "Unable to resolve domain for this request. Ensure DomainResolver is configured."))
                : oidcOptions.TokenValidationParameters.ValidIssuer;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidIssuer = validIssuer,
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
            context.Response.ContentType = "application/json";
            var json = System.Text.Json.JsonSerializer.Serialize(new { error, error_description = description });
            await context.Response.WriteAsync(json);
        }

        public static async Task WriteStatusCodeAsync(this HttpContext context, int statusCode)
        {
            context.Response.StatusCode = statusCode;
            await context.Response.WriteAsync(string.Empty);
        }
    }
}