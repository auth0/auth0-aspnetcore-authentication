using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

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
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddAuth0WebAppAuthentication(authenticationScheme, configureOptions);
        }
    }

    public static class EndpointRouteBuilderExtensions
    {
        public static void MapBackchannelEndpoint(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapPost("backchannel-logout", ProcessWith)
                .AllowAnonymous();
        }

        private static Task ProcessWith(HttpContext context)
        {
            var service = new BackchannelLogoutService();
            return service.ProcessRequestAsync(context);
        }
    }
}
