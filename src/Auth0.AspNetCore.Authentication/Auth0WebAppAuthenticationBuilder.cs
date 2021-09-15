using Microsoft.Extensions.DependencyInjection;
using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Builder to add functionality on top of OpenId Connect authentication. 
    /// </summary>
    public class Auth0WebAppAuthenticationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly Auth0WebAppOptions _options;

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services, Auth0WebAppOptions options)
        {
            _services = services;
            _options = options;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <returns>An instance of <see cref="Auth0WebAppWithAccessTokenAuthenticationBuilder"/></returns>
        public Auth0WebAppWithAccessTokenAuthenticationBuilder WithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            return new Auth0WebAppWithAccessTokenAuthenticationBuilder(_services, configureOptions, _options);
        }
    }
}
