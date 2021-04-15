using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace Auth0.AspNetCore.Mvc
{
    public static class Auth0ServiceCollectionExtensions
    {
        public static AuthenticationBuilder AddAuth0MVC(this IServiceCollection services, Action<Auth0Options> configureOptions)
        {
            return services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddAuth0MVC(configureOptions);
        }

    }
}
