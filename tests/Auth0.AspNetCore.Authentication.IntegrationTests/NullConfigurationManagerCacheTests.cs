using System;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class NullConfigurationManagerCacheTests
{
    [Fact]
    public void Constructor_CreatesInstance()
    {
        var cache = new NullConfigurationManagerCache();

        Assert.NotNull(cache);
    }

    [Fact]
    public void GetOrCreate_AlwaysInvokesFactory()
    {
        var cache = new NullConfigurationManagerCache();
        var callCount = 0;
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory = _ =>
        {
            callCount++;
            return mockManager.Object;
        };

        var metadataAddress = "https://example.auth0.com/.well-known/openid-configuration";
        cache.GetOrCreate(metadataAddress, factory);
        cache.GetOrCreate(metadataAddress, factory);
        cache.GetOrCreate(metadataAddress, factory);

        // Factory should be called every time
        Assert.Equal(3, callCount); 
    }

    [Fact]
    public void GetOrCreate_ReturnsFactoryResult()
    {
        var cache = new NullConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        var result = cache.GetOrCreate(
            "https://example.auth0.com/.well-known/openid-configuration",
            _ => mockManager.Object);

        Assert.Same(mockManager.Object, result);
    }

    [Fact]
    public void GetOrCreate_PassesMetadataAddressToFactory()
    {
        var cache = new NullConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        string? receivedAddress = null;

        var expectedAddress = "https://example.auth0.com/.well-known/openid-configuration";
        cache.GetOrCreate(expectedAddress, address =>
        {
            receivedAddress = address;
            return mockManager.Object;
        });

        Assert.Equal(expectedAddress, receivedAddress);
    }

    [Fact]
    public void Clear_DoesNotThrow()
    {
        var cache = new NullConfigurationManagerCache();

        var exception = Record.Exception(() => cache.Clear());

        Assert.Null(exception);
    }

    [Fact]
    public void Clear_CanBeCalledMultipleTimes()
    {
        var cache = new NullConfigurationManagerCache();

        var exception = Record.Exception(() =>
        {
            cache.Clear();
            cache.Clear();
            cache.Clear();
        });

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_DoesNotThrow()
    {
        var cache = new NullConfigurationManagerCache();

        var exception = Record.Exception(() => cache.Dispose());

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var cache = new NullConfigurationManagerCache();

        var exception = Record.Exception(() =>
        {
            cache.Dispose();
            cache.Dispose();
            cache.Dispose();
        });

        Assert.Null(exception);
    }

    [Fact]
    public void GetOrCreate_AfterDispose_StillWorks()
    {
        // NullConfigurationManagerCache should still work after Dispose
        // because it has no state to dispose
        var cache = new NullConfigurationManagerCache();
        var mockManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();

        cache.Dispose();

        var result = cache.GetOrCreate(
            "https://example.auth0.com/.well-known/openid-configuration",
            _ => mockManager.Object);

        Assert.Same(mockManager.Object, result);
    }
}
