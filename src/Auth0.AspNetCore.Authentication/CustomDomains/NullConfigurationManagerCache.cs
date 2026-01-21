using System;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// A pass-through cache implementation that does not cache configuration managers.
/// </summary>
/// <remarks>
/// Use this implementation when caching should be completely disabled.
/// Every call to <see cref="GetOrCreate"/> will invoke the factory to create a new 
/// configuration manager, which may impact performance but ensures fresh configuration manager instances.
/// </remarks>
/// <example>
/// <code>
/// // Disable caching
/// options.ConfigurationManagerCache = new NullConfigurationManagerCache();
/// </code>
/// </example>
public sealed class NullConfigurationManagerCache : IConfigurationManagerCache
{
    /// <inheritdoc />
    /// <remarks>
    /// This implementation always invokes the factory and never caches the result.
    /// </remarks>
    public IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory)
    {
        return factory(metadataAddress);
    }

    /// <inheritdoc />
    /// <remarks>
    /// This is a no-op since nothing is cached.
    /// </remarks>
    public void Clear()
    {
        // No-op: nothing to clear
    }

    /// <inheritdoc />
    /// <remarks>
    /// This is a no-op since there are no resources to dispose.
    /// </remarks>
    public void Dispose()
    {
        // No-op: nothing to dispose
    }
}
