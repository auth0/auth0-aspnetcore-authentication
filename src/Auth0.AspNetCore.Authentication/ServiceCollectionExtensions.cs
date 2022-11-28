using Microsoft.Extensions.DependencyInjection;
using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Contains <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> extension(s) for registering Auth0.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppOptions"/></param>
        /// <returns>The <see cref="Auth0WebAppAuthenticationBuilder"/> instance that has been created.</returns>
        public static Auth0WebAppAuthenticationBuilder AddAuth0WebAppAuthentication(this IServiceCollection services, Action<Auth0WebAppOptions> configureOptions)
        {
            return services.AddAuth0WebAppAuthentication(Auth0Constants.AuthenticationScheme, configureOptions);
        }

        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppOptions"/></param>
        /// <returns>The <see cref="Auth0WebAppAuthenticationBuilder"/> instance that has been created.</returns>
        public static Auth0WebAppAuthenticationBuilder AddAuth0WebAppAuthentication(this IServiceCollection services, string authenticationScheme, Action<Auth0WebAppOptions> configureOptions)
        {
            return services
                .AddAuthentication(options =>
                {
                    var authOptions = new Auth0WebAppOptions();

                    configureOptions(authOptions);

                    options.DefaultAuthenticateScheme = authOptions.CookieAuthenticationScheme;
                    options.DefaultSignInScheme = authOptions.CookieAuthenticationScheme;
                    options.DefaultChallengeScheme = authOptions.CookieAuthenticationScheme;
                })
                .AddAuth0WebAppAuthentication(authenticationScheme, configureOptions);
        }
    }
}
