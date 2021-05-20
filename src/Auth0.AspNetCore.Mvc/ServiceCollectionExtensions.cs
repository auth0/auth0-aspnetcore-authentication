using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Contains <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> extension(s) for registering Auth0.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="services">The original <see cref="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0Options"/></param>
        /// <returns>The <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationbuilder">AuthenticationBuilder</see> instance that has been created.</returns>
        public static AuthenticationBuilder AddAuth0Mvc(this IServiceCollection services, Action<Auth0Options> configureOptions)
        {
            return services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddAuth0Mvc(configureOptions);
        }

    }
}
