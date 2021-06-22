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

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Contains <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> extension(s) for registering Auth0.
    /// </summary>
    public static class AuthenticationBuilderExtensions
    {
        private static IList<string> codeResponseTypes = new List<string>() {
            OpenIdConnectResponseType.Code,
            OpenIdConnectResponseType.CodeIdToken
        };

        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="builder">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0Options"/></param>
        /// <returns>The <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance that has been configured.</returns>
        public static AuthenticationBuilder AddAuth0Mvc(this AuthenticationBuilder builder, Action<Auth0Options> configureOptions)
        {
            var auth0Options = new Auth0Options();

            configureOptions(auth0Options);
            ValidateOptions(auth0Options);

            builder.AddCookie(options =>
            {
                options.Events.OnValidatePrincipal = CreateOnValidatePrincipal(auth0Options);
            });
            builder.AddOpenIdConnect(Auth0Constants.AuthenticationScheme, options => ConfigureOpenIdConnect(options, auth0Options));

            builder.Services.AddSingleton(auth0Options);
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, Auth0OpenIdConnectPostConfigureOptions>());

            return builder;
        }

        /// <summary>
        /// Configure Open ID Connect based on the provided <see cref="Auth0Options"/>.
        /// </summary>
        /// <param name="oidcOptions">A reference to the <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectoptions">OpenIdConnectOptions</see> that needs to be configured./param>
        /// <param name="auth0Options">The provided <see cref="Auth0Options"/>.</param>
        private static void ConfigureOpenIdConnect(OpenIdConnectOptions oidcOptions, Auth0Options auth0Options)
        {
            oidcOptions.Authority = $"https://{auth0Options.Domain}";
            oidcOptions.ClientId = auth0Options.ClientId;
            oidcOptions.ClientSecret = auth0Options.ClientSecret;
            oidcOptions.Scope.Clear();
            oidcOptions.Scope.AddRange(auth0Options.Scope.Split(" "));
            oidcOptions.CallbackPath = new PathString(auth0Options.CallbackPath ?? Auth0Constants.DefaultCallbackPath);
            oidcOptions.SaveTokens = true;
            oidcOptions.ResponseType = auth0Options.ResponseType ?? oidcOptions.ResponseType;
            oidcOptions.Backchannel = auth0Options.Backchannel;
            oidcOptions.MaxAge = auth0Options.MaxAge;

            if (!oidcOptions.Scope.Contains("openid"))
            {
                oidcOptions.Scope.Add("openid");
            }

            if (auth0Options.UseRefreshTokens)
            {
                oidcOptions.Scope.AddSafe("offline_access");
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

        

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(Auth0Options auth0Options)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<Auth0Options>();

                string accessToken;
                if (context.Properties.Items.TryGetValue(".Token.access_token", out accessToken))
                {
                    if (options.UseRefreshTokens)
                    {
                        string refreshToken;
                        if (context.Properties.Items.TryGetValue(".Token.refresh_token", out refreshToken))
                        {
                            var now = DateTimeOffset.Now;
                            var expiresAt = DateTimeOffset.Parse(context.Properties.Items[".Token.expires_at"]);
                            var leeway = 60;
                            var difference = DateTimeOffset.Compare(expiresAt, now.AddSeconds(leeway));
                            var isExpired = difference <= 0;

                            if (isExpired && !string.IsNullOrWhiteSpace(refreshToken))
                            {
                                var result = await RefreshTokens(options, refreshToken, auth0Options.Backchannel);

                                if (result != null)
                                {
                                    context.Properties.UpdateTokenValue("access_token", result.AccessToken);
                                    context.Properties.UpdateTokenValue("refresh_token", result.RefreshToken);
                                    context.Properties.UpdateTokenValue("id_token", result.IdToken);
                                    context.Properties.UpdateTokenValue("expires_at", DateTimeOffset.Now.AddSeconds(result.ExpiresIn).ToString("o"));
                                }
                                else
                                {
                                    context.Properties.UpdateTokenValue("refresh_token", null);
                                }

                                context.ShouldRenew = true;

                            }
                        }
                        else
                        {
                            if (auth0Options.Events != null && auth0Options.Events.OnMissingRefreshToken != null)
                            {
                                await auth0Options.Events.OnMissingRefreshToken(context.HttpContext);
                            }
                        }
                    }
                }
                else
                {
                    if (codeResponseTypes.Contains(options.ResponseType))
                    {
                        if (auth0Options.Events != null && auth0Options.Events.OnMissingAccessToken != null)
                        {
                            await auth0Options.Events.OnMissingAccessToken(context.HttpContext);
                        }
                    }
                }
            };
        }

        private static void ValidateOptions(Auth0Options auth0Options)
        {
            if (codeResponseTypes.Contains(auth0Options.ResponseType) && string.IsNullOrWhiteSpace(auth0Options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(auth0Options.ClientSecret), "Client Secret can not be null when using `code` or `code id_token` as the response_type.");
            }

            if (!string.IsNullOrWhiteSpace(auth0Options.Audience) && !codeResponseTypes.Contains(auth0Options.ResponseType))
            {
                throw new InvalidOperationException("Using Audience is only supported when using `code` or `code id_token` as the response_type.");
            }

            if (auth0Options.UseRefreshTokens && !codeResponseTypes.Contains(auth0Options.ResponseType))
            {
                throw new InvalidOperationException("Using Refresh Tokens is only supported when using `code` or `code id_token` as the response_type.");
            }
        }

        private static async Task<AccessTokenResponse> RefreshTokens(Auth0Options options, string refreshToken, HttpClient httpClient = null)
        {
            using (var tokenClient = new TokenClient(httpClient))
            {
                return await tokenClient.Refresh(options, refreshToken);
            }
        }
    }
}
