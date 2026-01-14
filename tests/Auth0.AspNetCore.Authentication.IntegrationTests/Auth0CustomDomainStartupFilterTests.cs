using System;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0CustomDomainStartupFilterTests
{
    [Fact]
    public Task Configure_WithValidDomainResolver_StoresResolvedIssuerInHttpContext()
    {
        var auth0SchemeName = "Auth0";
        var expectedIssuer = "https://custom.domain.com";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult(expectedIssuer)
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => middleware(next)(httpContext).Wait());

        configureAction(appBuilder.Object);

        Assert.Equal(expectedIssuer, httpContext.Items[Auth0Constants.ResolvedDomainKey]);
        Assert.True(nextCalled);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithNullDomainResolver_DoesNotStoreIssuerInHttpContext()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = null
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        var nextCalled = false;
        RequestDelegate next = _ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => middleware(next)(httpContext).Wait());

        configureAction(appBuilder.Object);

        Assert.False(httpContext.Items.ContainsKey(Auth0Constants.ResolvedDomainKey));
        Assert.True(nextCalled);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithDomainResolverReturningNull_ThrowsInvalidOperationException()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult<string>(null)
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(async void (middleware) =>
                await Assert.ThrowsAsync<InvalidOperationException>(() => middleware(next)(httpContext)));

        configureAction(appBuilder.Object);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithDomainResolverReturningEmptyString_ThrowsInvalidOperationException()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult(string.Empty)
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();


        configureAction(appBuilder.Object);
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(async void (middleware) =>
                await Assert.ThrowsAsync<InvalidOperationException>(() => middleware(next)(httpContext)));
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithDomainResolverReturningWhitespace_ThrowsInvalidOperationException()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult("   ")
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(async void (middleware) =>
                await Assert.ThrowsAsync<InvalidOperationException>(() => middleware(next)(httpContext)));

        configureAction(appBuilder.Object);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_InvokesNextMiddlewareConfiguration()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var nextActionCalled = false;
        Action<IApplicationBuilder> nextAction = _ => { nextActionCalled = true; };

        var configureAction = startupFilter.Configure(nextAction);
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()));

        configureAction(appBuilder.Object);

        Assert.True(nextActionCalled);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithDifferentSchemeName_UsesCorrectScheme()
    {
        var auth0SchemeName = "CustomAuth0Scheme";
        var expectedIssuer = "https://custom.auth0.com";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult(expectedIssuer)
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => middleware(next)(httpContext).Wait());

        configureAction(appBuilder.Object);

        optionsMonitorMock.Verify(m => m.Get(auth0SchemeName), Times.Once);
        return Task.CompletedTask;
    }

    [Fact]
    public Task Configure_WithDomainResolverAccessingHttpContext_PassesCorrectContext()
    {
        var auth0SchemeName = "Auth0";
        var expectedPath = "/test-path";
        var capturedPath = string.Empty;
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = expectedPath;
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = ctx =>
            {
                capturedPath = ctx.Request.Path;
                return Task.FromResult("https://domain.com");
            }
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => middleware(next)(httpContext).Wait());

        configureAction(appBuilder.Object);

        Assert.Equal(expectedPath, capturedPath);
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Configure_WithDomainResolverThrowing_PropagatesException()
    {
        var auth0SchemeName = "Auth0";
        var expectedException = new InvalidOperationException("Domain resolution failed");
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        var httpContext = new DefaultHttpContext();
        var serviceCollection = new ServiceCollection();
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => throw expectedException
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        serviceCollection.AddSingleton(optionsMonitorMock.Object);
        httpContext.RequestServices = serviceCollection.BuildServiceProvider();
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        Func<RequestDelegate, RequestDelegate> capturedMiddleware = null;
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => capturedMiddleware = middleware);

        configureAction(appBuilder.Object);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await capturedMiddleware(next)(httpContext));
        Assert.Equal("Domain resolution failed", exception.Message);
    }

    [Fact]
    public async Task Configure_WithConcurrentRequestsWithDifferentDomains_IsolatesResolvedDomains()
    {
        var auth0SchemeName = "Auth0";
        var startupFilter = new Auth0CustomDomainStartupFilter(auth0SchemeName);
        
        // Create two HTTP contexts with different host headers
        var httpContext1 = new DefaultHttpContext();
        httpContext1.Request.Host = new HostString("tenant1.example.com");
        var serviceCollection1 = new ServiceCollection();
        
        var httpContext2 = new DefaultHttpContext();
        httpContext2.Request.Host = new HostString("tenant2.example.com");
        var serviceCollection2 = new ServiceCollection();

        // Domain resolver that uses the host to determine the domain
        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = ctx => Task.FromResult($"https://{ctx.Request.Host.Host}.auth0.com")
        };
        
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(auth0SchemeName)).Returns(customDomainsOptions);
        
        serviceCollection1.AddSingleton(optionsMonitorMock.Object);
        serviceCollection2.AddSingleton(optionsMonitorMock.Object);
        
        httpContext1.RequestServices = serviceCollection1.BuildServiceProvider();
        httpContext2.RequestServices = serviceCollection2.BuildServiceProvider();
        
        RequestDelegate next = _ => Task.CompletedTask;

        var configureAction = startupFilter.Configure(_ => { });
        var appBuilder = new Mock<IApplicationBuilder>();
        Func<RequestDelegate, RequestDelegate> capturedMiddleware = null;
        appBuilder.Setup(a => a.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Callback<Func<RequestDelegate, RequestDelegate>>(middleware => capturedMiddleware = middleware);

        configureAction(appBuilder.Object);

        // Execute both requests concurrently
        var task1 = capturedMiddleware(next)(httpContext1);
        var task2 = capturedMiddleware(next)(httpContext2);
        await Task.WhenAll(task1, task2);

        // Verify each context has its own resolved domain
        Assert.Equal("https://tenant1.example.com.auth0.com", httpContext1.Items[Auth0Constants.ResolvedDomainKey]);
        Assert.Equal("https://tenant2.example.com.auth0.com", httpContext2.Items[Auth0Constants.ResolvedDomainKey]);
    }
}