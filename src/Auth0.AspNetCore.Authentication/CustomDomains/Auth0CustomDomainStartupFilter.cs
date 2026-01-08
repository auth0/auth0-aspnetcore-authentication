using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// A startup filter that integrates Auth0 custom domain resolution into the ASP.NET Core pipeline.
/// </summary>
internal sealed class Auth0CustomDomainStartupFilter : IStartupFilter
{
    private readonly string _auth0SchemeName;

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0CustomDomainStartupFilter"/> class.
    /// </summary>
    /// <param name="auth0SchemeName">The name of the Auth0 authentication scheme.</param>
    public Auth0CustomDomainStartupFilter(string auth0SchemeName)
        => _auth0SchemeName = auth0SchemeName;

    /// <summary>
    /// Configures the middleware pipeline to resolve and cache the Auth0 custom domain for each request.
    /// </summary>
    /// <param name="next">The next middleware configuration action in the pipeline.</param>
    /// <returns>An action that configures the application builder.</returns>
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            app.Use(async (ctx, nxt) =>
            {
                // Retrieve the Auth0 custom domain options for the specified scheme.
                var monitor = ctx.RequestServices.GetRequiredService<IOptionsMonitor<Auth0CustomDomainsOptions>>();
                var customDomainsOptions = monitor.Get(_auth0SchemeName);

                // If a DomainResolver is defined, resolve the issuer and cache it in the HttpContext.
                if (customDomainsOptions.DomainResolver is not null)
                {
                    var issuer = await customDomainsOptions.DomainResolver(ctx);
                    if (string.IsNullOrWhiteSpace(issuer))
                        throw new InvalidOperationException("DomainResolver returned empty issuer.");
                    
                    ctx.Items[Auth0Constants.ResolvedDomainKey] = issuer;
                }

                // Proceed to the next middleware in the pipeline.
                await nxt();
            });

            // Invoke the next middleware configuration action.
            next(app);
        };
    }
}
