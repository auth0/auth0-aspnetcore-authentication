using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Builder to add functionality on top of OpenId Connect authentication. 
    /// </summary>
    public class Auth0WebAppAuthenticationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly Auth0WebAppOptions _options;
        private readonly string _authenticationScheme;

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services, Auth0WebAppOptions options) : this(services, Auth0Constants.AuthenticationScheme, options)
        {
        }

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="authenticationScheme">The authentication scheme to use.</param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services, string authenticationScheme, Auth0WebAppOptions options)
        {
            _services = services;
            _options = options;
            _authenticationScheme = authenticationScheme;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            EnableWithAccessToken(configureOptions);
            return this;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithBackchannelLogout()
        {
            _services.AddTransient<BackchannelLogoutHandler>();
            _services.AddTransient<ILogoutTokenHandler, DefaultLogoutTokenHandler>();
            return this;
        }

        private void EnableWithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            var auth0WithAccessTokensOptions = new Auth0WebAppWithAccessTokenOptions();

            configureOptions(auth0WithAccessTokensOptions);

            ValidateOptions(_options);

            _services.Configure(_authenticationScheme, configureOptions);
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
