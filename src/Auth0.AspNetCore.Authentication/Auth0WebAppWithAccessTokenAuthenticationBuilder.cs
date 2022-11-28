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

        private static void ValidateOptions(Auth0WebAppOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(options.ClientSecret), "Client Secret can not be null when requesting an access token.");
            }
        }

    }
}
