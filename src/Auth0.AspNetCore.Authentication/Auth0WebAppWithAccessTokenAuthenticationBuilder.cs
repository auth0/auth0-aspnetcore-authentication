using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Builder to add extra functionality when using Access Tokens. 
    /// </summary>
    public class Auth0WebAppWithAccessTokenAuthenticationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly Action<Auth0WebAppWithAccessTokenOptions> _configureOptions;
        private readonly Auth0WebAppOptions _options;
        private readonly string _authenticationScheme;

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
            : this(services, configureOptions, options, Auth0Constants.AuthenticationScheme)
        {
        }

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppWithAccessTokenAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        /// <param name="authenticationScheme">The authentication scheme to use.</param>
        public Auth0WebAppWithAccessTokenAuthenticationBuilder(IServiceCollection services, Action<Auth0WebAppWithAccessTokenOptions> configureOptions, Auth0WebAppOptions options, string authenticationScheme)
        {
            _services = services;
            _configureOptions = configureOptions;
            _options = options;
            _authenticationScheme = authenticationScheme;

            EnableWithAccessToken();
        }

        private void EnableWithAccessToken()
        {
            var auth0WithAccessTokensOptions = new Auth0WebAppWithAccessTokenOptions();

            _configureOptions(auth0WithAccessTokensOptions);

            ValidateOptions(_options);

            _services.Configure(_authenticationScheme, _configureOptions);
            _services.AddOptions<OpenIdConnectOptions>(_authenticationScheme)
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

                    options.Events.OnRedirectToIdentityProvider = Utils.ProxyEvent(CreateOnRedirectToIdentityProvider(_authenticationScheme), options.Events.OnRedirectToIdentityProvider);
                });

            _services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure(options =>
                {
                    options.Events.OnValidatePrincipal = Utils.ProxyEvent(CreateOnValidatePrincipal(_authenticationScheme), options.Events.OnValidatePrincipal);
                });
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(string authenticationScheme)
        {
            return (context) =>
            {
                var optionsWithAccessToken = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(authenticationScheme);

                if (!string.IsNullOrWhiteSpace(optionsWithAccessToken.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", optionsWithAccessToken.Audience);
                }

                if (context.Properties.Items.ContainsKey(Auth0AuthenticationParameters.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", context.Properties.Items[Auth0AuthenticationParameters.Audience]);
                }

                return Task.CompletedTask;
            };
        }

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(string authenticationScheme)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(authenticationScheme);
                var optionsWithAccessToken = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(authenticationScheme);
                var oidcOptions = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>().Get(authenticationScheme);

                if (context.Properties.Items.TryGetValue(".AuthScheme", out var authScheme))
                {
                    if (!string.IsNullOrEmpty(authScheme) && authScheme != authenticationScheme)
                    {
                        return;
                    }
                }

                var accessToken = context.Properties.GetTokenValue("access_token");
                if (!string.IsNullOrEmpty(accessToken))
                {
                    if (optionsWithAccessToken.UseRefreshTokens)
                    {
                        var refreshToken = context.Properties.GetTokenValue("refresh_token");
                        if (!string.IsNullOrEmpty(refreshToken))
                        {
                            var now = DateTimeOffset.Now;
                            var expiresAt = DateTimeOffset.Parse(context.Properties.GetTokenValue("expires_at")!);
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
            if (string.IsNullOrWhiteSpace(options.ClientSecret) && options.ClientAssertionSecurityKey == null)
            {
                throw new InvalidOperationException("Both Client Secret and Client Assertion can not be null when requesting an access token, one or the other has to be set.");
            }

            if (!string.IsNullOrWhiteSpace(options.ClientSecret) && options.ClientAssertionSecurityKey != null)
            {
                throw new InvalidOperationException("Both Client Secret and Client Assertion can not be set at the same time when requesting an access token.");
            }
        }

    }
}
