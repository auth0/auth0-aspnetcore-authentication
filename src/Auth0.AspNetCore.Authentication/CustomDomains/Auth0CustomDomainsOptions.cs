using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

public class Auth0CustomDomainsOptions
{
    /// <summary>
    /// Resolves the Domain (issuer) for the current request.
    /// </summary>
    /// <example>
    /// Resolves to a domain like <c>tenant.auth0.com</c> based on the request.
    /// </example>
    public Func<HttpContext, Task<string>>? DomainResolver { get; set; }
    
    /// <summary>
    /// Indicates whether multiple custom domains are enabled by checking if <see cref="DomainResolver"/> is set.
    /// </summary>
    internal bool IsMultipleCustomDomainsEnabled => DomainResolver != null;
}