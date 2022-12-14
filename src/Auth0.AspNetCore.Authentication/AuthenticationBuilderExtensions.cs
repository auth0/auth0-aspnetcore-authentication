using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Contains <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> extension(s) for registering Auth0.
    /// </summary>
    public static class AuthenticationBuilderExtensions
    {
        private static readonly IList<string> CodeResponseTypes = new List<string>() {
            OpenIdConnectResponseType.Code,
            OpenIdConnectResponseType.CodeIdToken
        };

        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="builder">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppOptions"/></param>
        /// <returns>The <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance that has been configured.</returns>

        public static Auth0WebAppAuthenticationBuilder AddAuth0WebAppAuthentication(this AuthenticationBuilder builder, Action<Auth0WebAppOptions> configureOptions)
        {
            return AddAuth0WebAppAuthentication(builder, Auth0Constants.AuthenticationScheme, configureOptions);
        }

        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="builder">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance</param>
        /// <param name="authenticationScheme">The authentication scheme to use.</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppOptions"/></param>
        /// <returns>The <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance that has been configured.</returns>

        public static Auth0WebAppAuthenticationBuilder AddAuth0WebAppAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<Auth0WebAppOptions> configureOptions)
        {
            var auth0Options = new Auth0WebAppOptions();

            configureOptions(auth0Options);
            ValidateOptions(auth0Options);

            builder.AddOpenIdConnect(authenticationScheme, options => ConfigureOpenIdConnect(options, auth0Options));

            if (!auth0Options.SkipCookieMiddleware)
            {
                builder.AddCookie();
            }

            builder.Services.Configure(authenticationScheme, configureOptions);
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, Auth0OpenIdConnectPostConfigureOptions>());

            builder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure(options =>
                {
                    options.Events.OnValidatePrincipal = Utils.ProxyEvent(CreateOnValidatePrincipal(authenticationScheme), options.Events.OnValidatePrincipal);
                });

            return new Auth0WebAppAuthenticationBuilder(builder.Services, authenticationScheme, auth0Options);
        }

        /// <summary>
        /// Configure Open ID Connect based on the provided <see cref="Auth0WebAppOptions"/>.
        /// </summary>
        /// <param name="oidcOptions">A reference to the <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectoptions">OpenIdConnectOptions</see> that needs to be configured.</param>
        /// <param name="auth0Options">The provided <see cref="Auth0WebAppOptions"/>.</param>
        private static void ConfigureOpenIdConnect(OpenIdConnectOptions oidcOptions, Auth0WebAppOptions auth0Options)
        {
            oidcOptions.Authority = $"https://{auth0Options.Domain}";
            oidcOptions.ClientId = auth0Options.ClientId;
            oidcOptions.ClientSecret = auth0Options.ClientSecret;
            oidcOptions.Scope.Clear();
            oidcOptions.Scope.AddRange(auth0Options.Scope.Split(" "));
            oidcOptions.CallbackPath = new PathString(auth0Options.CallbackPath ?? Auth0Constants.DefaultCallbackPath);
            oidcOptions.SaveTokens = true;
            oidcOptions.ResponseType = auth0Options.ResponseType ?? oidcOptions.ResponseType;
            oidcOptions.Backchannel = auth0Options.Backchannel!;
            oidcOptions.MaxAge = auth0Options.MaxAge;

            if (!oidcOptions.Scope.Contains("openid"))
            {
                oidcOptions.Scope.Add("openid");
            }

            oidcOptions.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                ValidateAudience = true,
                ValidAudience = auth0Options.ClientId,
                ValidateIssuer = true,
                ValidIssuer = $"https://{auth0Options.Domain}/",
                ValidateLifetime = true,
                RequireExpirationTime = true,
            };

            oidcOptions.Events = OpenIdConnectEventsFactory.Create(auth0Options);
        }

        private static void ValidateOptions(Auth0WebAppOptions auth0Options)
        {
            if (CodeResponseTypes.Contains(auth0Options.ResponseType!) && string.IsNullOrWhiteSpace(auth0Options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(auth0Options.ClientSecret), "Client Secret can not be null when using `code` or `code id_token` as the response_type.");
            }
        }

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(string authenticationScheme)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(authenticationScheme);
                var optionsWithAccessToken = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(authenticationScheme);
                var oidcOptions = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>().Get(authenticationScheme);
                var logoutTokenHandler = context.HttpContext.RequestServices.GetRequiredService<ILogoutTokenHandler>();

                if (context.Properties.Items.TryGetValue(".AuthScheme", out var authScheme))
                {
                    if (!string.IsNullOrEmpty(authScheme) && authScheme != authenticationScheme)
                    {
                        return;
                    }
                }

                var issuer = $"https://{options.Domain}/";
                var sid = context.Principal?.FindFirst("sid")?.Value;

                var isLoggedOut = await logoutTokenHandler.IsLoggedOutAsync(issuer, sid);

                if (isLoggedOut)
                {
                    // Log out the user
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync();

                    // Temporary for testing
                    // We shouldn't actualy remove anything
                    await logoutTokenHandler.RemoveAsync(issuer, sid);

                }

                if (optionsWithAccessToken == null)
                {
                    return;
                }

                await RefreshTokenIfNeccesary(context, options, optionsWithAccessToken, oidcOptions);
            };
        }

        private static async Task RefreshTokenIfNeccesary(CookieValidatePrincipalContext context, Auth0WebAppOptions options, Auth0WebAppWithAccessTokenOptions optionsWithAccessToken, OpenIdConnectOptions oidcOptions)
        {
            if (context.Properties.Items.TryGetValue(".Token.access_token", out _))
            {
                if (optionsWithAccessToken.UseRefreshTokens)
                {
                    if (context.Properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken))
                    {
                        var now = DateTimeOffset.Now;
                        var expiresAt = DateTimeOffset.Parse(context.Properties.Items[".Token.expires_at"]!);
                        var leeway = 60;
                        var difference = DateTimeOffset.Compare(expiresAt, now.AddSeconds(leeway));
                        var isExpired = difference <= 0;

                        if (isExpired && !string.IsNullOrWhiteSpace(refreshToken))
                        {
                            var result = await RefreshTokens(options, refreshToken, oidcOptions.Backchannel);

                            if (result != null)
                            {
                                context.Properties.UpdateTokenValue("access_token", result.AccessToken);
                                if (!string.IsNullOrEmpty(result.RefreshToken))
                                {
                                    context.Properties.UpdateTokenValue("refresh_token", result.RefreshToken);
                                }
                                context.Properties.UpdateTokenValue("id_token", result.IdToken);
                                context.Properties.UpdateTokenValue("expires_at", DateTimeOffset.Now.AddSeconds(result.ExpiresIn).ToString("o"));
                            }
                            else
                            {
                                context.Properties.UpdateTokenValue("refresh_token", null!);
                            }

                            context.ShouldRenew = true;

                        }
                    }
                    else
                    {
                        if (optionsWithAccessToken.Events?.OnMissingRefreshToken != null)
                        {
                            await optionsWithAccessToken.Events.OnMissingRefreshToken(context.HttpContext);
                        }
                    }
                }
            }
            else
            {
                if (CodeResponseTypes.Contains(options.ResponseType!))
                {
                    if (optionsWithAccessToken.Events?.OnMissingAccessToken != null)
                    {
                        await optionsWithAccessToken.Events.OnMissingAccessToken(context.HttpContext);
                    }
                }
            }
        }

        private static async Task<AccessTokenResponse?> RefreshTokens(Auth0WebAppOptions options, string refreshToken, HttpClient? httpClient = null)
        {
            using (var tokenClient = new TokenClient(httpClient))
            {
                return await tokenClient.Refresh(options, refreshToken);
            }
        }
    }
}
