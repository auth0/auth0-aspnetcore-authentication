using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Caching.Memory;

namespace Auth0.AspNetCore.Mvc
{
    public interface ITokenCacheProvider
    {

    }

    public class TokenCacheEntry
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class MemoryTokenCacheProvider : ITokenCacheProvider
    {
        /// <summary>
        /// .NET Core Memory cache.
        /// </summary>
        private readonly IMemoryCache _memoryCache;

        public MemoryTokenCacheProvider(IMemoryCache memoryCache)
        {
            _memoryCache = memoryCache;
        }

        public Task Remove(string key)
        {
            _memoryCache.Remove(key);

            return Task.CompletedTask;
        }

        public Task<TokenCacheEntry> Get(string key)
        {
            return Task.FromResult(_memoryCache.Get<TokenCacheEntry>(key));
        }

        public Task Set(string key, TokenCacheEntry value)
        {
            _memoryCache.Set(key, value);
            return Task.CompletedTask;
        }
    }
    /// <summary>
    /// Builder to add extra functionality when using Access Tokens. 
    /// </summary>
    public class Auth0WebAppWithAccessTokenAuthenticationBuilder
    {

        private static readonly IList<string> CodeResponseTypes = new List<string>() {
            OpenIdConnectResponseType.Code,
            OpenIdConnectResponseType.CodeIdToken
        };

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppWithAccessTokenAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see cref="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        public Auth0WebAppWithAccessTokenAuthenticationBuilder(IServiceCollection services, Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            Services = services;
            ConfigureOptions = configureOptions;

            EnableWithAccessToken();
        }

        public IServiceCollection Services { get; private set; }
        public Action<Auth0WebAppWithAccessTokenOptions> ConfigureOptions { get; private set; }

        private void EnableWithAccessToken()
        {
            var auth0WithAccessTokensOptions = new Auth0WebAppWithAccessTokenOptions();

            ConfigureOptions(auth0WithAccessTokensOptions);
            

            Services.AddSingleton(auth0WithAccessTokensOptions);
            Services.AddOptions<OpenIdConnectOptions>(Auth0Constants.AuthenticationScheme)
                .Configure<IServiceProvider>((options, serviceProvider) =>
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

                    options.Events.OnAuthorizationCodeReceived = Utils.ProxyEvent(CreateOnAuthorizationCodeReceived(auth0WithAccessTokensOptions), options.Events.OnAuthorizationCodeReceived);
                });

            Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure<IServiceProvider>((options, serviceProvider) =>
                {
                    options.Events.OnValidatePrincipal = Utils.ProxyEvent(CreateOnValidatePrincipal(auth0WithAccessTokensOptions), options.Events.OnValidatePrincipal);
                });
        }

        public void WithInMemoryStorage()
        {
            Services.AddMemoryCache();
            Services.AddHttpContextAccessor();


            // Services.AddSingleton<TokenCacheProvider, MemoryTokenCacheProvider>();
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

        private static Func<AuthorizationCodeReceivedContext, Task> CreateOnAuthorizationCodeReceived(Auth0WebAppWithAccessTokenOptions auth0Options)
        {
            return async (context) =>
            {

                var options = context.HttpContext.RequestServices.GetRequiredService<Auth0WebAppOptions>();

                // Exchange Code for a Token
                var idToken = "";

                //string codeVerifier = "";
                context.TokenEndpointRequest.Parameters.TryGetValue("code", out string code);
                context.TokenEndpointRequest.Parameters.TryGetValue(OAuthConstants.CodeVerifierKey, out string codeVerifier);
                context.TokenEndpointRequest.Parameters.TryGetValue("redirect_uri", out string redirectUri);

                context.Properties.Items.TryGetValue(Auth0AuthenticationParameters.Organization, out string organization);
                

                using (var authClient = new AuthenticationApiClient(options.Domain))
                {
                    try
                    {
                        var result = await authClient.GetTokenAsync(new AuthorizationCodePkceTokenRequest()
                        {
                            ClientId = options.ClientId,
                            ClientSecret = options.ClientSecret,
                            Code = code,
                            CodeVerifier = codeVerifier,
                            Organization = organization,
                            RedirectUri = redirectUri 

                        }).ConfigureAwait(false);

                        context.HandleCodeRedemption(null, result.IdToken);
                    }
                    catch (Exception e)
                    {

                    }
                }
            };
        }

        private static Func<CookieValidatePrincipalContext, Task> CreateOnValidatePrincipal(Auth0WebAppWithAccessTokenOptions auth0Options)
        {
            return async (context) =>
            {
                var options = context.HttpContext.RequestServices.GetRequiredService<Auth0WebAppOptions>();

                string accessToken;
                if (context.Properties.Items.TryGetValue(".Token.access_token", out accessToken))
                {
                    if (auth0Options.UseRefreshTokens)
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
                    if (CodeResponseTypes.Contains(options.ResponseType))
                    {
                        if (auth0Options.Events != null && auth0Options.Events.OnMissingAccessToken != null)
                        {
                            await auth0Options.Events.OnMissingAccessToken(context.HttpContext);
                        }
                    }
                }
            };
        }

        private static async Task<AccessTokenResponse> RefreshTokens(Auth0WebAppOptions options, string refreshToken, HttpClient httpClient = null)
        {
            using (var tokenClient = new TokenClient(httpClient))
            {
                return await tokenClient.Refresh(options, refreshToken);
            }
        }

    }
}
