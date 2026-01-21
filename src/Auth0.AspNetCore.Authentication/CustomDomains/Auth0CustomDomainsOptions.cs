using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// Options for configuring Auth0 custom domains support.
/// </summary>
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
    /// Cache implementation for OpenID Connect configuration managers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If not set, a default <see cref="MemoryConfigurationManagerCache"/> is used with 
    /// 100 entries and no expiration.
    /// </para>
    /// <para>
    /// To customize the default cache settings:
    /// <code>
    /// options.ConfigurationManagerCache = new MemoryConfigurationManagerCache(
    ///     maxSize: 50,
    ///     slidingExpiration: TimeSpan.FromHours(1)
    /// );
    /// </code>
    /// </para>
    /// <para>
    /// To disable caching:
    /// <code>
    /// options.ConfigurationManagerCache = new NullConfigurationManagerCache();
    /// </code>
    /// </para>
    /// <para>
    /// To provide a custom cache implementation, implement <see cref="IConfigurationManagerCache"/>.
    /// </para>
    /// </remarks>
    public IConfigurationManagerCache? ConfigurationManagerCache { get; set; }
    
    /// <summary>
    /// Indicates whether multiple custom domains are enabled by checking if <see cref="DomainResolver"/> is set.
    /// </summary>
    internal bool IsMultipleCustomDomainsEnabled => DomainResolver != null;
}