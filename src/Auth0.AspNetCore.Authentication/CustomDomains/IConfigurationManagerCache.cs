using System;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// Abstraction for caching OpenID Connect configuration managers.
/// </summary>
/// <remarks>
/// Implement this interface to provide custom caching behavior for configuration managers.
/// The SDK provides two built-in implementations:
/// <list type="bullet">
/// <item><description><see cref="MemoryConfigurationManagerCache"/> - Default in-memory cache using MemoryCache</description></item>
/// <item><description><see cref="NullConfigurationManagerCache"/> - No-op cache that disables caching</description></item>
/// </list>
/// </remarks>
/// <example>
/// <code>
/// // Custom implementation example
/// public class CustomCache : IConfigurationManagerCache
/// {
///     public IConfigurationManager&lt;OpenIdConnectConfiguration&gt; GetOrCreate(
///         string metadataAddress,
///         Func&lt;string, IConfigurationManager&lt;OpenIdConnectConfiguration&gt;&gt; factory)
///     {
///         // Your caching logic here
///         // returns a ConfigurationManager Instance from cache or create a new one;
///     }
///     
///     public void Clear() { /* Clear your cache */ }
///     public void Dispose() { /* Cleanup resources */ }
/// }
/// </code>
/// </example>
public interface IConfigurationManagerCache : IDisposable
{
    /// <summary>
    /// Gets an existing configuration manager from the cache or creates a new one using the factory.
    /// </summary>
    /// <param name="metadataAddress">The OIDC metadata endpoint URL, used as the cache key.</param>
    /// <param name="factory">Factory function to create a new configuration manager if not cached.</param>
    /// <returns>The cached or newly created configuration manager.</returns>
    IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory);

    /// <summary>
    /// Clears all cached entries.
    /// </summary>
    /// <remarks>
    /// This method is called when <see cref="IConfigurationManager{T}.RequestRefresh"/> is invoked
    /// on the parent configuration manager.
    /// </remarks>
    void Clear();
}
