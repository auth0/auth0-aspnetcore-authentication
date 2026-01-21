using System;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// Default in-memory cache implementation using <see cref="MemoryCache"/>.
/// </summary>
/// <remarks>
/// Default cache used when no custom <see cref="IConfigurationManagerCache"/> is provided.
/// Supports configurable size limits and sliding expiration.
/// </remarks>
/// <example>
/// <code>
/// // With default settings (100 entries, no expiration)
/// options.ConfigurationManagerCache = new MemoryConfigurationManagerCache();
/// 
/// // With custom settings
/// options.ConfigurationManagerCache = new MemoryConfigurationManagerCache(
///     maxSize: 50,
///     slidingExpiration: TimeSpan.FromHours(1)
/// );
/// </code>
/// </example>
public sealed class MemoryConfigurationManagerCache : IConfigurationManagerCache
{
    /// <summary>
    /// The default maximum number of entries in the cache.
    /// </summary>
    public const int DefaultMaxSize = 100;
    
    private readonly MemoryCache _cache;
    private readonly TimeSpan? _slidingExpiration;
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="MemoryConfigurationManagerCache"/> class.
    /// </summary>
    /// <param name="maxSize">
    /// Maximum number of configuration managers to cache. Default is 100.
    /// </param>
    /// <param name="slidingExpiration">
    /// Optional sliding expiration for cached entries. When set, entries that haven't 
    /// been accessed within this duration will be removed on the next cache operation.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when maxSize is less than 1.</exception>
    public MemoryConfigurationManagerCache(
        int maxSize = DefaultMaxSize,
        TimeSpan? slidingExpiration = null)
    {
        if (maxSize < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxSize), "MaxSize must be at least 1.");
        }
        
        _slidingExpiration = slidingExpiration;
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = maxSize
        });
    }

    /// <inheritdoc />
    public IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory)
    {
        ThrowIfDisposed();
        
        // Fast path: check cache without lock
        if (_cache.TryGetValue(metadataAddress, out IConfigurationManager<OpenIdConnectConfiguration>? cached) && cached != null)
        {
            return cached;
        }
        
        // Slow path: acquire lock and double-check
        lock (_lock)
        {
            // Double-check after acquiring lock
            if (_cache.TryGetValue(metadataAddress, out cached) && cached != null)
            {
                return cached;
            }
            
            var manager = factory(metadataAddress);
            
            var cacheOptions = new MemoryCacheEntryOptions { Size = 1 };
            if (_slidingExpiration.HasValue)
            {
                cacheOptions.SlidingExpiration = _slidingExpiration.Value;
            }
            
            _cache.Set(metadataAddress, manager, cacheOptions);
            
            return manager;
        }
    }

    /// <inheritdoc />
    public void Clear()
    {
        if (_disposed)
        {
            return;
        }
        
        _cache.Compact(1.0);
    }
    
    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if this instance has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        
        _disposed = true;
        _cache.Dispose();
    }
}
