using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0CustomDomainsOpenIdConnectConfigurationManagerTests
{
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
    private readonly Mock<Func<HttpContext, Task<string>>> _domainResolverMock;
    private readonly Mock<ISecureDataFormat<AuthenticationProperties>> _stateDataFormatMock;
    private readonly HttpClient _httpClient;
    private readonly DefaultHttpContext _httpContext;

    public Auth0CustomDomainsOpenIdConnectConfigurationManagerTests()
    {
        _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
        _domainResolverMock = new Mock<Func<HttpContext, Task<string>>>();
        _stateDataFormatMock = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        _httpClient = new HttpClient();
        _httpContext = new DefaultHttpContext();
    }

    [Fact]
    public void Constructor_WithNullHttpContextAccessor_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            null!,
            _domainResolverMock.Object,
            _stateDataFormatMock.Object,
            _httpClient));
    }

    [Fact]
    public void Constructor_WithNullDomainResolver_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            _httpContextAccessorMock.Object,
            null!,
            _stateDataFormatMock.Object,
            _httpClient));
    }

    [Fact]
    public void Constructor_WithNullStateDataFormat_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            _httpContextAccessorMock.Object,
            _domainResolverMock.Object,
            null!,
            _httpClient));
    }

    [Fact]
    public void Constructor_WithNullHttpClient_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            _httpContextAccessorMock.Object,
            _domainResolverMock.Object,
            _stateDataFormatMock.Object,
            null!));
    }

    [Fact]
    public async Task GetConfigurationAsync_WithNullHttpContext_ThrowsInvalidOperationException()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns((HttpContext)null!);
        var manager = CreateManager();

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                manager.GetConfigurationAsync(CancellationToken.None));

        Assert.Contains("HttpContext is not available", exception.Message);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithValidHttpContext_ReturnsConfiguration()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>())).ReturnsAsync("example.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient);

        var configuration = await manager.GetConfigurationAsync(CancellationToken.None);

        Assert.NotNull(configuration);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithSameDomainMultipleTimes_ReusesCachedConfigurationManager()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>())).ReturnsAsync("example.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient);

        var config1= await manager.GetConfigurationAsync(CancellationToken.None);
        var config2 = await manager.GetConfigurationAsync(CancellationToken.None);

        domainResolver.Verify(x => x(It.IsAny<HttpContext>()), Times.Once);
        config1.Issuer.Should().NotBeNullOrWhiteSpace();
        config2.Issuer.Should().NotBeNullOrWhiteSpace();
        
        config1.Issuer?.Should().Be(config2.Issuer);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithDifferentDomains_CreatesSeparateConfigurationManagers()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var callCount = 0;
        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>()))
            .ReturnsAsync(() => callCount++ == 0 ? "domain1.auth0.com" : "domain2.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient);

        httpContext.Items.Clear();
        var config1 = await manager.GetConfigurationAsync(CancellationToken.None);

        httpContext.Items.Clear();
        var config2 = await manager.GetConfigurationAsync(CancellationToken.None);

        Assert.NotNull(config1);
        Assert.True(config1.Issuer?.Contains("domain1.auth0.com"));
        Assert.NotNull(config2);
        Assert.True(config2.Issuer?.Contains("domain2.auth0.com"));
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithValidDomainResolver_ReturnsDomain()
    {
        var expectedDomain = "tenant.auth0.com";
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync(expectedDomain);
        var manager = CreateManager();

        var authority = await manager.ResolveAuthorityAsync(_httpContext);

        Assert.Equal($"https://{expectedDomain}/", authority);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithNullDomain_ThrowsInvalidOperationException()
    {
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync((string)null!);
        var manager = CreateManager();

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.ResolveAuthorityAsync(_httpContext));

        Assert.Contains("DomainResolver returned a null or empty value", exception.Message);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithEmptyDomain_ThrowsInvalidOperationException()
    {
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync(string.Empty);
        var manager = CreateManager();

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.ResolveAuthorityAsync(_httpContext));

        Assert.Contains("DomainResolver returned a null or empty value", exception.Message);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithWhitespaceDomain_ThrowsInvalidOperationException()
    {
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync("   ");
        var manager = CreateManager();

        var exception =
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.ResolveAuthorityAsync(_httpContext));

        Assert.Contains("DomainResolver returned a null or empty value", exception.Message);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_CachesDomainInHttpContextItems()
    {
        var expectedDomain = "tenant.auth0.com";
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync(expectedDomain);
        var manager = CreateManager();

        await manager.ResolveAuthorityAsync(_httpContext);

        Assert.Equal(expectedDomain, _httpContext.Items[Auth0Constants.ResolvedDomainKey]);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_UsesCachedDomainFromHttpContextItems()
    {
        var cachedDomain = "cached.auth0.com";
        _httpContext.Items[Auth0Constants.ResolvedDomainKey] = cachedDomain;
        var manager = CreateManager();

        var authority = await manager.ResolveAuthorityAsync(_httpContext);

        Assert.Equal($"https://{cachedDomain}/", authority);
        _domainResolverMock.Verify(x => x(It.IsAny<HttpContext>()), Times.Never);
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithStateParameter_ExtractsIssuerFromState()
    {
        var issuer = "state-domain.auth0.com";
        var state = "protected-state";
        _httpContext.Request.QueryString = new QueryString($"?state={state}");

        var props = new AuthenticationProperties();
        props.Items[Auth0Constants.ResolvedDomainKey] = issuer;
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Returns(props);

        var manager = CreateManager();

        var authority = await manager.ResolveAuthorityAsync(_httpContext);

        Assert.Equal($"https://{issuer}/", authority);
        _domainResolverMock.Verify(x => x(It.IsAny<HttpContext>()), Times.Never);
    }

    [Fact]
    public void TryGetState_WithQueryStringState_ReturnsTrue()
    {
        var expectedState = "test-state";
        _httpContext.Request.QueryString = new QueryString($"?state={expectedState}");

        var result = Auth0CustomDomainsOpenIdConnectConfigurationManager.TryGetState(_httpContext, out var state);

        Assert.True(result);
        Assert.Equal(expectedState, state);
    }

    [Fact]
    public void TryGetState_WithFormState_ReturnsTrue()
    {
        var expectedState = "form-state";
        _httpContext.Request.ContentType = "application/x-www-form-urlencoded";
        var formCollection = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "state", expectedState }
        });
        _httpContext.Request.Form = formCollection;

        var result = Auth0CustomDomainsOpenIdConnectConfigurationManager.TryGetState(_httpContext, out var state);

        Assert.True(result);
        Assert.Equal(expectedState, state);
    }

    [Fact]
    public void TryGetState_WithNoState_ReturnsFalse()
    {
        var result = Auth0CustomDomainsOpenIdConnectConfigurationManager.TryGetState(_httpContext, out var state);

        Assert.False(result);
        Assert.Null(state);
    }

    [Fact]
    public void TryGetState_WithEmptyQueryState_ReturnsFalse()
    {
        _httpContext.Request.QueryString = new QueryString("?state=");

        var result = Auth0CustomDomainsOpenIdConnectConfigurationManager.TryGetState(_httpContext, out var state);

        Assert.False(result);
        Assert.Null(state);
    }

    [Fact]
    public void TryGetState_PrefersQueryStringOverForm()
    {
        var queryState = "query-state";
        var formState = "form-state";
        _httpContext.Request.QueryString = new QueryString($"?state={queryState}");
        _httpContext.Request.ContentType = "application/x-www-form-urlencoded";
        var formCollection = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "state", formState }
        });
        _httpContext.Request.Form = formCollection;

        var result = Auth0CustomDomainsOpenIdConnectConfigurationManager.TryGetState(_httpContext, out var state);

        Assert.True(result);
        Assert.Equal(queryState, state);
    }

    [Fact]
    public void TryGetIssuerFromState_WithValidState_ReturnsTrue()
    {
        var expectedIssuer = "tenant.auth0.com";
        var state = "protected-state";
        var props = new AuthenticationProperties();
        props.Items[Auth0Constants.ResolvedDomainKey] = expectedIssuer;
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Returns(props);
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.True(result);
        Assert.Equal(expectedIssuer, issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithNullState_ReturnsFalse()
    {
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(null, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithEmptyState_ReturnsFalse()
    {
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(string.Empty, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithWhitespaceState_ReturnsFalse()
    {
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState("   ", out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithCryptographicException_ReturnsFalse()
    {
        var state = "invalid-state";
        _stateDataFormatMock.Setup(x => x.Unprotect(state))
            .Throws<System.Security.Cryptography.CryptographicException>();
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithFormatException_ReturnsFalse()
    {
        var state = "invalid-state";
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Throws<FormatException>();
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithArgumentException_ReturnsFalse()
    {
        var state = "invalid-state";
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Throws<ArgumentException>();
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithNullProperties_ReturnsFalse()
    {
        var state = "protected-state";
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Returns((AuthenticationProperties)null!);
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithMissingDomainKey_ReturnsFalse()
    {
        var state = "protected-state";
        var props = new AuthenticationProperties();
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Returns(props);
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void TryGetIssuerFromState_WithEmptyDomainValue_ReturnsFalse()
    {
        var state = "protected-state";
        var props = new AuthenticationProperties();
        props.Items[Auth0Constants.ResolvedDomainKey] = string.Empty;
        _stateDataFormatMock.Setup(x => x.Unprotect(state)).Returns(props);
        var manager = CreateManager();

        var result = manager.TryGetIssuerFromState(state, out var issuer);

        Assert.False(result);
        Assert.Empty(issuer);
    }

    [Fact]
    public void CreateConfigurationManager_WithHttpsAddress_RequiresHttps()
    {
        var address = "https://tenant.auth0.com/.well-known/openid-configuration";
        var manager = CreateManager();

        var configManager = manager.CreateConfigurationManager(address);

        Assert.NotNull(configManager);
    }

    [Fact]
    public void CreateConfigurationManager_WithHttpAddress_DoesNotRequireHttps()
    {
        var address = "http://localhost/.well-known/openid-configuration";
        var manager = CreateManager();

        var configManager = manager.CreateConfigurationManager(address);

        Assert.NotNull(configManager);
    }

    [Fact]
    public void RequestRefresh_CallsRequestRefreshOnAllCachedManagers()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns(_httpContext);
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync("tenant1.auth0.com");
        var manager = CreateManager();

        manager.RequestRefresh();
    }

    [Fact]
    public async Task ResolveAuthorityAsync_WithTrailingSlashInDomain_TrimsSlash()
    {
        var domainWithSlash = "tenant.auth0.com/";
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync(domainWithSlash);
        var manager = CreateManager();

        var authority = await manager.ResolveAuthorityAsync(_httpContext);

        Assert.Equal("https://tenant.auth0.com/", authority);
    }

    private Auth0CustomDomainsOpenIdConnectConfigurationManager CreateManager(IConfigurationManagerCache? cache = null)
    {
        return new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            _httpContextAccessorMock.Object,
            _domainResolverMock.Object,
            _stateDataFormatMock.Object,
            _httpClient,
            cache);
    }

    [Fact]
    public void Constructor_WithNullCache_CreatesDefaultCache()
    {
        var manager = CreateManager(cache: null);

        Assert.NotNull(manager);
    }

    [Fact]
    public void Constructor_WithCustomCache_UsesProvidedCache()
    {
        var customCache = new MemoryConfigurationManagerCache(maxSize: 50);
        var manager = CreateManager(cache: customCache);

        Assert.NotNull(manager);
    }

    [Fact]
    public void Constructor_WithNullConfigurationManagerCache_UsesProvidedCache()
    {
        var nullCache = new NullConfigurationManagerCache();
        var manager = CreateManager(cache: nullCache);

        Assert.NotNull(manager);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithNullCache_AlwaysCreatesNewManager()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>())).ReturnsAsync("example.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();
        var nullCache = new NullConfigurationManagerCache();

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient,
            nullCache);

        httpContext.Items.Clear();
        var config1 = await manager.GetConfigurationAsync(CancellationToken.None);

        httpContext.Items.Clear();
        var config2 = await manager.GetConfigurationAsync(CancellationToken.None);

        // With NullConfigurationManagerCache, the domain resolver should be called each time
        // since no caching is performed
        domainResolver.Verify(x => x(It.IsAny<HttpContext>()), Times.Exactly(2));
        Assert.NotNull(config1);
        Assert.NotNull(config2);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithCustomMemoryCache_ReusesCachedManager()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>())).ReturnsAsync("example.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();
        var memoryCache = new MemoryConfigurationManagerCache(maxSize: 10);

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient,
            memoryCache);

        var config1 = await manager.GetConfigurationAsync(CancellationToken.None);
        var config2 = await manager.GetConfigurationAsync(CancellationToken.None);

        // With MemoryConfigurationManagerCache, the domain resolver should only be called once
        // due to caching
        domainResolver.Verify(x => x(It.IsAny<HttpContext>()), Times.Once);
        Assert.NotNull(config1);
        Assert.NotNull(config2);
    }

    [Fact]
    public void Dispose_WithOwnedCache_DisposesCache()
    {
        // When no cache is provided, the manager creates and owns its own cache
        var manager = CreateManager(cache: null);

        var exception = Record.Exception(() => manager.Dispose());

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_WithProvidedCache_DoesNotDisposeCache()
    {
        // When a cache is provided externally, the manager should not dispose it
        var customCache = new MemoryConfigurationManagerCache(maxSize: 50);
        var manager = CreateManager(cache: customCache);

        manager.Dispose();

        // The cache should still be usable after manager disposal
        var mockConfigManager = new Mock<IConfigurationManager<OpenIdConnectConfiguration>>();
        var exception = Record.Exception(() => customCache.GetOrCreate("test", _ => mockConfigManager.Object));

        Assert.Null(exception);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var manager = CreateManager();

        var exception = Record.Exception(() =>
        {
            manager.Dispose();
            manager.Dispose();
            manager.Dispose();
        });

        Assert.Null(exception);
    }

    [Fact]
    public async Task GetConfigurationAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns(_httpContext);
        _domainResolverMock.Setup(x => x(_httpContext)).ReturnsAsync("example.auth0.com");
        var manager = CreateManager();

        manager.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            manager.GetConfigurationAsync(CancellationToken.None));
    }

    [Fact]
    public void RequestRefresh_AfterDispose_DoesNotThrow()
    {
        var manager = CreateManager();

        manager.Dispose();

        // RequestRefresh gracefully handles disposal by returning early
        var exception = Record.Exception(() => manager.RequestRefresh());

        Assert.Null(exception);
    }

    [Fact]
    public async Task GetConfigurationAsync_WithMemoryCacheAndSlidingExpiration_UsesCache()
    {
        var httpContext = new DefaultHttpContext();
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        httpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var domainResolver = new Mock<Func<HttpContext, Task<string>>>();
        domainResolver.Setup(x => x(It.IsAny<HttpContext>())).ReturnsAsync("example.auth0.com");

        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();
        var memoryCache = new MemoryConfigurationManagerCache(maxSize: 10, slidingExpiration: TimeSpan.FromHours(1));

        var manager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
            httpContextAccessor.Object,
            domainResolver.Object,
            stateDataFormat.Object,
            httpClient,
            memoryCache);

        var config = await manager.GetConfigurationAsync(CancellationToken.None);

        Assert.NotNull(config);
    }
}