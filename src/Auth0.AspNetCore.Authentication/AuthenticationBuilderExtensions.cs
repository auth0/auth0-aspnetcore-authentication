using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication
{
    public static class OpenIdConnectConfigurationKeys
    {
        public static string BACKCHANNEL_LOGOUT_SUPPORTED = "backchannel_logout_supported";
        public static string BACKCHANNEL_LOGOUT_SESSION_SUPPORTED = "backchannel_logout_session_supported";
    }
    
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
                builder.AddCookie(auth0Options.CookieAuthenticationScheme);
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
            oidcOptions.SaveTokens = auth0Options.SaveTokens;
            oidcOptions.ResponseType = auth0Options.ResponseType ?? oidcOptions.ResponseType;
            oidcOptions.Backchannel = auth0Options.Backchannel!;
            oidcOptions.MaxAge = auth0Options.MaxAge;
            oidcOptions.AccessDeniedPath = auth0Options.AccessDeniedPath;
            oidcOptions.SignInScheme = auth0Options.SignInScheme;
            oidcOptions.ForwardSignIn = auth0Options.ForwardSignIn;
            oidcOptions.SignOutScheme = auth0Options.SignOutScheme;
            oidcOptions.ForwardSignOut = auth0Options.ForwardSignOut;

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
            oidcOptions.Events = OpenIdConnectEventsFactory.Create(auth0Options, oidcOptions);
        }

        private static void ValidateOptions(Auth0WebAppOptions auth0Options)
        {
            if (CodeResponseTypes.Contains(auth0Options.ResponseType!))
            {
                if (string.IsNullOrWhiteSpace(auth0Options.ClientSecret) && auth0Options.ClientAssertionSecurityKey == null)
                {
                    throw new InvalidOperationException("Both Client Secret and Client Assertion can not be null when using `code` or `code id_token` as the response_type.");
                }

                if (!string.IsNullOrWhiteSpace(auth0Options.ClientSecret) && auth0Options.ClientAssertionSecurityKey != null)
                {
                    throw new InvalidOperationException("Both Client Secret and Client Assertion can not be set at the same time when using `code` or `code id_token` as the response_type.");
                }
            }
        }

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(string authenticationScheme)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(authenticationScheme);
                var optionsWithAccessToken = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(authenticationScheme);
                var oidcOptions = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>().Get(authenticationScheme);
                var logoutTokenHandler = context.HttpContext.RequestServices.GetService<ILogoutTokenHandler>();

                if (context.Properties.Items.TryGetValue(".AuthScheme", out var authScheme))
                {
                    if (!string.IsNullOrEmpty(authScheme) && authScheme != authenticationScheme)
                    {
                        return;
                    }
                }

                if (logoutTokenHandler != null)
                {
                    await VerifyBackchannelLogoutSupport(context.HttpContext, oidcOptions);

                    var issuer = $"https://{options.Domain}/";
                    var sid = context.Principal?.FindFirst("sid")?.Value;

                    var isLoggedOut = await logoutTokenHandler.IsLoggedOutAsync(issuer, sid);

                    if (isLoggedOut)
                    {
                        // Log out the user
                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync();

                        return;
                    }
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

        private static async Task<AccessTokenResponse?> RefreshTokens(Auth0WebAppOptions options, string refreshToken, HttpClient httpClient)
        {
            var tokenClient = new TokenClient(httpClient);
            return await tokenClient.Refresh(options, refreshToken);
        }

        private static async Task VerifyBackchannelLogoutSupport(HttpContext context, OpenIdConnectOptions oidcOptions)
        {
            if (oidcOptions.Configuration == null)
            {
                oidcOptions.Configuration = await oidcOptions.ConfigurationManager.GetConfigurationAsync(context.RequestAborted);
            }

            var additionalConfiguration = oidcOptions.Configuration.AdditionalData;
            var supported = (additionalConfiguration?.GetBooleanOrDefault(OpenIdConnectConfigurationKeys.BACKCHANNEL_LOGOUT_SUPPORTED, false) ?? false);
            var sessionSupported = additionalConfiguration?.GetBooleanOrDefault(OpenIdConnectConfigurationKeys.BACKCHANNEL_LOGOUT_SESSION_SUPPORTED, false) ?? false;

            if (!supported || !sessionSupported)
            {
                var loggerFactory = context.RequestServices.GetService<ILoggerFactory>();

                if (loggerFactory != null)
                {
                    var logger = loggerFactory.CreateLogger("Auth0");
                    logger.LogWarning("Configured back-channel logout, but OIDC configuration indicates lack of support.");
                }
            }
        }
    }
}
