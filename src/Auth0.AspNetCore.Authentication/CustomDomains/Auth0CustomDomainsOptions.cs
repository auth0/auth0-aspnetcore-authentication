using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

public class Auth0CustomDomainsOptions
{
    /// <summary>
    /// Resolves the Domain (issuer) for the current request.
    /// </summary>
    /// <remarks>
    /// This function is called for each authentication request to dynamically determine
    /// which Auth0 custom domain should handle the request. The returned value should
    /// be just the domain without protocol or paths.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.DomainResolver = async (context) =>
    /// {
    ///     var tenant = context.Request.Host.Host.Split('.').First();
    ///     return $"{tenant}.auth0.com";
    /// };
    /// </code>
    /// </example>
    public Func<HttpContext, Task<string>>? DomainResolver { get; set; }
    
    /// <summary>
    /// Indicates whether multiple custom domains are enabled by checking if <see cref="DomainResolver"/> is set.
    /// </summary>
    internal bool IsMultipleCustomDomainsEnabled => DomainResolver != null;
}