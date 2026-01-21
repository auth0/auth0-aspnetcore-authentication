using System;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0CustomDomainsOpenIdConnectPostConfigureOptionsTests
{
    [Fact]
    public void Constructor_WithNullHttpContextAccessor_ThrowsArgumentNullException()
    {
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();

        var exception = Assert.Throws<ArgumentNullException>(() =>
            new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
                null!,
                auth0CustomDomainsOptionsMonitor.Object));

        Assert.Equal("httpContextAccessor", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithNullAuth0CustomDomainsOptionsMonitor_ThrowsArgumentNullException()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();

        var exception = Assert.Throws<ArgumentNullException>(() =>
            new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
                httpContextAccessor.Object,
                null!));

        Assert.Equal("auth0CustomDomainsOptionsMonitor", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithValidParameters_DoesNotThrow()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();

        var exception = Record.Exception(() =>
            new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
                httpContextAccessor.Object,
                auth0CustomDomainsOptionsMonitor.Object));

        Assert.Null(exception);
    }

    [Fact]
    public void Constructor_WithHttpClientFactory_DoesNotThrow()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        var httpClientFactory = new Mock<IHttpClientFactory>();

        var exception = Record.Exception(() =>
            new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
                httpContextAccessor.Object,
                auth0CustomDomainsOptionsMonitor.Object,
                httpClientFactory.Object));

        Assert.Null(exception);
    }

    [Fact]
    public void PostConfigure_WithNullName_DoesNotModifyOptions()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        var options = new OpenIdConnectOptions();
        var originalConfigurationManager = options.ConfigurationManager;

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure(null, options);

        Assert.Equal(originalConfigurationManager, options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithEmptyName_DoesNotModifyOptions()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        var options = new OpenIdConnectOptions();
        var originalConfigurationManager = options.ConfigurationManager;

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure(string.Empty, options);

        Assert.Equal(originalConfigurationManager, options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WhenMultipleCustomDomainsDisabled_DoesNotModifyOptions()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions();
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions();
        var originalConfigurationManager = options.ConfigurationManager;

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.Equal(originalConfigurationManager, options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WhenStateDataFormatIsNull_ThrowsInvalidOperationException()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = null
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            postConfigureOptions.PostConfigure("TestScheme", options));

        Assert.Contains("StateDataFormat is not configured", exception.Message);
    }

    [Fact]
    public void PostConfigure_WithValidConfiguration_SetsConfigurationManager()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.IsType<Auth0CustomDomainsOpenIdConnectConfigurationManager>(options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithValidConfiguration_DisablesIssuerValidation()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.False(options.TokenValidationParameters.ValidateIssuer);
    }

    [Fact]
    public void PostConfigure_WithValidConfiguration_ClearsAuthority()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Authority = "https://example.auth0.com",
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.Null(options.Authority);
    }

    [Fact]
    public void PostConfigure_WithHttpClientFactory_UsesFactoryClient()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var httpClient = new HttpClient();
        var httpClientFactory = new Mock<IHttpClientFactory>();
        httpClientFactory.Setup(f => f.CreateClient(string.Empty)).Returns(httpClient);

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object,
            httpClientFactory.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        httpClientFactory.Verify(f => f.CreateClient(string.Empty), Times.Once);
        Assert.NotNull(options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithBackchannel_UsesBackchannel()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var backchannel = new HttpClient();
        var httpClientFactory = new Mock<IHttpClientFactory>();

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = backchannel
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object,
            httpClientFactory.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        httpClientFactory.Verify(f => f.CreateClient(It.IsAny<string>()), Times.Never);
        Assert.NotNull(options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithoutBackchannelOrFactory_ThrowsInvalidOperationException()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            postConfigureOptions.PostConfigure("TestScheme", options));

        Assert.Contains("Either OpenIdConnectOptions.Backchannel or IHttpClientFactory must be configured", exception.Message);
    }

    [Fact]
    public void PostConfigure_WithCustomCache_UsesProvidedCache()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();
        var customCache = new MemoryConfigurationManagerCache(maxSize: 50);

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
            ConfigurationManagerCache = customCache
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.IsType<Auth0CustomDomainsOpenIdConnectConfigurationManager>(options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithNullCache_UsesDefaultCache()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
            ConfigurationManagerCache = null
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.IsType<Auth0CustomDomainsOpenIdConnectConfigurationManager>(options.ConfigurationManager);
    }

    [Fact]
    public void PostConfigure_WithNullConfigurationManagerCache_DisablesCaching()
    {
        var httpContextAccessor = new Mock<IHttpContextAccessor>();
        var stateDataFormat = new Mock<ISecureDataFormat<AuthenticationProperties>>();

        var auth0CustomDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = context => Task.FromResult<string>(null),
            ConfigurationManagerCache = new NullConfigurationManagerCache()
        };
        var auth0CustomDomainsOptionsMonitor = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        auth0CustomDomainsOptionsMonitor.Setup(m => m.Get("TestScheme")).Returns(auth0CustomDomainsOptions);

        var options = new OpenIdConnectOptions
        {
            StateDataFormat = stateDataFormat.Object,
            Backchannel = new HttpClient()
        };

        var postConfigureOptions = new Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            httpContextAccessor.Object,
            auth0CustomDomainsOptionsMonitor.Object);

        postConfigureOptions.PostConfigure("TestScheme", options);

        Assert.IsType<Auth0CustomDomainsOpenIdConnectConfigurationManager>(options.ConfigurationManager);
    }
}