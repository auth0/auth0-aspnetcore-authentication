using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class MemoryConfigurationManagerCacheTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_WithInvalidMaxSize_ThrowsArgumentOutOfRangeException(int maxSize)
    {
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MemoryConfigurationManagerCache(maxSize: maxSize));

        Assert.Equal("maxSize", exception.ParamName);
    }

    [Fact]
    public void GetOrCreate_WithValidParameters_ReturnsConfigurationManager()
    {
        var cache = new MemoryConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        var result = cache.GetOrCreate(
            "https://example.auth0.com/.well-known/openid-configuration",
            _ => mockManager.Object);

        Assert.Same(mockManager.Object, result);
    }

    [Fact]
    public void GetOrCreate_CalledTwiceWithSameKey_ReturnsSameInstance()
    {
        var cache = new MemoryConfigurationManagerCache();
        var callCount = 0;
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory = _ =>
        {
            callCount++;
            return mockManager.Object;
        };

        var metadataAddress = "https://example.auth0.com/.well-known/openid-configuration";
        var result1 = cache.GetOrCreate(metadataAddress, factory);
        var result2 = cache.GetOrCreate(metadataAddress, factory);

        Assert.Same(result1, result2);
        // Factory should only be called once
        Assert.Equal(1, callCount);
    }

    [Fact]
    public void GetOrCreate_CalledWithDifferentKeys_ReturnsDifferentInstances()
    {
        var cache = new MemoryConfigurationManagerCache();
        var mockManager1 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var mockManager2 = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var callCount = 0;

        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory = address =>
        {
            callCount++;
            return address.Contains("domain1") ? mockManager1.Object : mockManager2.Object;
        };

        var result1 = cache.GetOrCreate("https://domain1.auth0.com/.well-known/openid-configuration", factory);
        var result2 = cache.GetOrCreate("https://domain2.auth0.com/.well-known/openid-configuration", factory);

        Assert.NotSame(result1, result2);
        Assert.Equal(2, callCount);
    }

    [Fact]
    public void GetOrCreate_AfterDispose_ThrowsObjectDisposedException()
    {
        var cache = new MemoryConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        cache.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            cache.GetOrCreate("https://example.auth0.com/.well-known/openid-configuration", _ => mockManager.Object));
    }

    [Fact]
    public void Clear_DoesNotThrow()
    {
        var cache = new MemoryConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        // Add an entry
        cache.GetOrCreate("https://example.auth0.com/.well-known/openid-configuration", _ => mockManager.Object);

        // Should not throw
        var exception = Record.Exception(() => cache.Clear());
        Assert.Null(exception);
    }

    [Fact]
    public void Clear_AfterDispose_DoesNotThrow()
    {
        var cache = new MemoryConfigurationManagerCache();
        cache.Dispose();

        // Should not throw even after disposal
        var exception = Record.Exception(() => cache.Clear());
        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var cache = new MemoryConfigurationManagerCache();

        var exception = Record.Exception(() =>
        {
            cache.Dispose();
            cache.Dispose();
            cache.Dispose();
        });

        Assert.Null(exception);
    }

    [Fact]
    public void DefaultMaxSize_IsOneHundred()
    {
        Assert.Equal(100, MemoryConfigurationManagerCache.DefaultMaxSize);
    }
    
    [Fact]
    public async Task GetOrCreate_ConcurrentCallsWithSameKey_InvokesFactoryOnlyOnce()
    {
        // Arrange
        var cache = new MemoryConfigurationManagerCache();
        var factoryCallCount = 0;
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
    
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory = _ =>
        {
            Interlocked.Increment(ref factoryCallCount);
            // Simulate slow factory to increase chance of race condition
            Thread.Sleep(500);
            return mockManager.Object;
        };

        var metadataAddress = "https://example.auth0.com/.well-known/openid-configuration";
    
        // Simulates concurrent calls
        var tasks = Enumerable.Range(0, 100)
            .Select(_ => Task.Run(() => cache.GetOrCreate(metadataAddress, factory)))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        // Assert - Factory should only be invoked once
        Assert.Equal(1, factoryCallCount);
        Assert.All(results, result => Assert.Same(mockManager.Object, result));
    }
}
