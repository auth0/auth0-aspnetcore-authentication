using Microsoft.Extensions.DependencyInjection;
using System;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Builder to add functionality on top of OpenId Connect authentication. 
    /// </summary>
    public class Auth0WebAppAuthenticationBuilder
    {
        private readonly IServiceCollection services;

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see cref="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services)
        {
            this.services = services;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <returns>An instance of <see cref="Auth0WebAppWithAccessTokenAuthenticationBuilder"/></returns>
        public Auth0WebAppWithAccessTokenAuthenticationBuilder WithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            return new Auth0WebAppWithAccessTokenAuthenticationBuilder(this.services, configureOptions);
        }
    }
}
