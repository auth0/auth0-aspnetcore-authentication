using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Builder to add extra functionality when using Access Tokens. 
    /// </summary>
    public class Auth0WebAppWithAccessTokenAuthenticationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly Action<Auth0WebAppWithAccessTokenOptions> _configureOptions;
        private readonly Auth0WebAppOptions _options;

        private static readonly IList<string> CodeResponseTypes = new List<string>() {
            OpenIdConnectResponseType.Code,
            OpenIdConnectResponseType.CodeIdToken
        };

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppWithAccessTokenAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppWithAccessTokenAuthenticationBuilder(IServiceCollection services, Action<Auth0WebAppWithAccessTokenOptions> configureOptions, Auth0WebAppOptions options)
        {
            _services = services;
            _configureOptions = configureOptions;
            _options = options;

            EnableWithAccessToken();
        }

        private void EnableWithAccessToken()
        {
            var auth0WithAccessTokensOptions = new Auth0WebAppWithAccessTokenOptions();

            _configureOptions(auth0WithAccessTokensOptions);
            
            ValidateOptions(_options);

            _services.AddSingleton(auth0WithAccessTokensOptions);
            _services.AddOptions<OpenIdConnectOptions>(Auth0Constants.AuthenticationScheme)
                .Configure(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.Code;

                    if (!string.IsNullOrEmpty(auth0WithAccessTokensOptions.Scope))
                    {
                        options.Scope.AddRange(auth0WithAccessTokensOptions.Scope.Split(" "));
                    }

                    if (auth0WithAccessTokensOptions.UseRefreshTokens)
                    {
                        options.Scope.AddSafe("offline_access");
                    }

                    options.Events.OnRedirectToIdentityProvider = Utils.ProxyEvent(CreateOnRedirectToIdentityProvider(auth0WithAccessTokensOptions), options.Events.OnRedirectToIdentityProvider);
                });

            _services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure(options =>
                {
                    options.Events.OnValidatePrincipal = Utils.ProxyEvent(CreateOnValidatePrincipal(auth0WithAccessTokensOptions), options.Events.OnValidatePrincipal);
                });
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(Auth0WebAppWithAccessTokenOptions auth0Options)
        {
            return (context) =>
            {
                if (!string.IsNullOrWhiteSpace(auth0Options.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", auth0Options.Audience);
                }

                if (context.Properties.Items.ContainsKey(Auth0AuthenticationParameters.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", context.Properties.Items[Auth0AuthenticationParameters.Audience]);
                }

                return Task.CompletedTask;
            };
        }

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(Auth0WebAppWithAccessTokenOptions auth0Options)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<Auth0WebAppOptions>();

                if (context.Properties.Items.TryGetValue(".Token.access_token", out _))
                {
                    if (auth0Options.UseRefreshTokens)
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
                                var result = await RefreshTokens(options, refreshToken, options.Backchannel);

                                if (result != null)
                                {
                                    context.Properties.UpdateTokenValue("access_token", result.AccessToken);
                                    context.Properties.UpdateTokenValue("refresh_token", result.RefreshToken);
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
                            if (auth0Options.Events?.OnMissingRefreshToken != null)
                            {
                                await auth0Options.Events.OnMissingRefreshToken(context.HttpContext);
                            }
                        }
                    }
                }
                else
                {
                    if (CodeResponseTypes.Contains(options.ResponseType!))
                    {
                        if (auth0Options.Events?.OnMissingAccessToken != null)
                        {
                            await auth0Options.Events.OnMissingAccessToken(context.HttpContext);
                        }
                    }
                }
            };
        }

        private static async Task<AccessTokenResponse?> RefreshTokens(Auth0WebAppOptions options, string refreshToken, HttpClient? httpClient = null)
        {
            using (var tokenClient = new TokenClient(httpClient))
            {
                return await tokenClient.Refresh(options, refreshToken);
            }
        }

        private static void ValidateOptions(Auth0WebAppOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(options.ClientSecret), "Client Secret can not be null when requesting an access token.");
            }
        }

    }
}
