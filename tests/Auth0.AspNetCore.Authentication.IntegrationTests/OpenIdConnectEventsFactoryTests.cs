using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

/// <summary>
/// Tests for the OnRedirectToIdentityProvider event handler in OpenIdConnectEventsFactory,
/// specifically covering the MCD (Multiple Custom Domains) domain-resolution logic.
/// </summary>
public class OpenIdConnectEventsFactoryTests
{
    // -------------------------------------------------------------------------
    // Unit-level tests: invoke the OIDC event delegate directly without a full
    // TestServer. This lets us precisely control HttpContext.Items.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task OnRedirectToIdentityProvider_WhenMcdEnabled_AndDomainMissingFromHttpContextItems_Returns500()
    {
        // Arrange — MCD enabled but HttpContext.Items has no ResolvedDomainKey
        var auth0Options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "client1" };
        var oidcOptions = new OpenIdConnectOptions();

        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult("tenant.custom.com")
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(It.IsAny<string>())).Returns(customDomainsOptions);

        var services = new ServiceCollection();
        services.AddSingleton(optionsMonitorMock.Object);
        var serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = serviceProvider };
        // Deliberately do NOT set Auth0Constants.ResolvedDomainKey in httpContext.Items

        var responseBody = new MemoryStream();
        httpContext.Response.Body = responseBody;

        var events = OpenIdConnectEventsFactory.Create(auth0Options, oidcOptions);

        var scheme = new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler));
        var properties = new AuthenticationProperties();
        var redirectContext = new RedirectContext(httpContext, scheme, oidcOptions, properties)
        {
            ProtocolMessage = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage()
        };

        // Act
        await events.OnRedirectToIdentityProvider(redirectContext);

        // Assert — response must be 500, redirect must NOT have occurred
        httpContext.Response.StatusCode.Should().Be(500);

        responseBody.Seek(0, SeekOrigin.Begin);
        var body = await new StreamReader(responseBody).ReadToEndAsync();
        body.Should().Contain("Authentication configuration error");
        body.Should().Contain("could not resolve the domain");

        // The properties items must NOT contain the resolved domain key (no domain was stored)
        properties.Items.Should().NotContainKey(Auth0Constants.ResolvedDomainKey);
    }

    [Fact]
    public async Task OnRedirectToIdentityProvider_WhenMcdEnabled_AndDomainPresentInHttpContextItems_StoresDomainInState()
    {
        // Arrange — MCD enabled and HttpContext.Items contains the resolved domain
        var auth0Options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "client1" };
        var oidcOptions = new OpenIdConnectOptions();

        var customDomainsOptions = new Auth0CustomDomainsOptions
        {
            DomainResolver = _ => Task.FromResult("tenant.custom.com")
        };
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(It.IsAny<string>())).Returns(customDomainsOptions);

        var services = new ServiceCollection();
        services.AddSingleton(optionsMonitorMock.Object);
        var serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = serviceProvider };
        httpContext.Items[Auth0Constants.ResolvedDomainKey] = "tenant.custom.com";

        var events = OpenIdConnectEventsFactory.Create(auth0Options, oidcOptions);

        var scheme = new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler));
        var properties = new AuthenticationProperties();
        var redirectContext = new RedirectContext(httpContext, scheme, oidcOptions, properties)
        {
            ProtocolMessage = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage()
        };

        // Act
        await events.OnRedirectToIdentityProvider(redirectContext);

        // Assert — domain must be stored in state, response must NOT be 500
        httpContext.Response.StatusCode.Should().NotBe(500);
        properties.Items.Should().ContainKey(Auth0Constants.ResolvedDomainKey);
        properties.Items[Auth0Constants.ResolvedDomainKey].Should().Be("tenant.custom.com");
    }

    [Fact]
    public async Task OnRedirectToIdentityProvider_WhenMcdDisabled_DoesNotTouchResolvedDomainKey()
    {
        // Arrange — MCD disabled (no DomainResolver configured)
        var auth0Options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "client1" };
        var oidcOptions = new OpenIdConnectOptions();

        var customDomainsOptions = new Auth0CustomDomainsOptions(); // DomainResolver = null → MCD disabled
        var optionsMonitorMock = new Mock<IOptionsMonitor<Auth0CustomDomainsOptions>>();
        optionsMonitorMock.Setup(m => m.Get(It.IsAny<string>())).Returns(customDomainsOptions);

        var services = new ServiceCollection();
        services.AddSingleton(optionsMonitorMock.Object);
        var serviceProvider = services.BuildServiceProvider();

        var httpContext = new DefaultHttpContext { RequestServices = serviceProvider };

        var events = OpenIdConnectEventsFactory.Create(auth0Options, oidcOptions);

        var scheme = new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler));
        var properties = new AuthenticationProperties();
        var redirectContext = new RedirectContext(httpContext, scheme, oidcOptions, properties)
        {
            ProtocolMessage = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage()
        };

        // Act
        await events.OnRedirectToIdentityProvider(redirectContext);

        // Assert — MCD logic not entered; no domain stored, response not affected
        httpContext.Response.StatusCode.Should().NotBe(500);
        properties.Items.Should().NotContainKey(Auth0Constants.ResolvedDomainKey);
    }

    // -------------------------------------------------------------------------
    // Integration-level test: full TestServer with MCD enabled and a working
    // DomainResolver + mocked OIDC discovery.
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Should_Redirect_To_CustomDomain_Authorize_WhenMcdEnabled()
    {
        // Arrange — mock OIDC discovery for the custom domain
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .Build();

        var customDomain = "tenant.custom.com";
        IDictionary<string, string?> capturedItems = null;

        using var server = TestServerBuilder.CreateServer(
            configureOptions: opts =>
            {
                opts.Backchannel = new HttpClient(mockHandler.Object);
                opts.OpenIdConnectEvents = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = ctx =>
                    {
                        // Runs AFTER the SDK's handler, so ResolvedDomainKey should already be set
                        capturedItems = new Dictionary<string, string?>(ctx.Properties.Items);
                        return Task.CompletedTask;
                    }
                };
            },
            configureCustomDomains: cdOpts =>
            {
                cdOpts.DomainResolver = _ => Task.FromResult(customDomain);
            });

        using var client = server.CreateClient();

        // Act
        var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");

        // Assert — the MCD flow resolved the domain, fetched OIDC config for it, and redirected to
        // the /authorize endpoint returned by the mocked discovery (wellknownconfig.json uses
        // "tenant.eu.auth0.com" as the authorization_endpoint host).
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        response.Headers.Location.Should().NotBeNull();
        response.Headers.Location.AbsolutePath.Should().Be("/authorize");

        // Verify the resolved domain was stored in the authentication state
        capturedItems.Should().NotBeNull();
        capturedItems.Should().ContainKey(Auth0Constants.ResolvedDomainKey);
        capturedItems[Auth0Constants.ResolvedDomainKey].Should().Be(customDomain);
    }

    [Fact]
    public async Task Should_Throw_WhenDomainResolver_ReturnsEmpty()
    {
        // Arrange — DomainResolver returns empty, which should cause the startup filter to fail fast
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .Build();

        using var server = TestServerBuilder.CreateServer(
            configureOptions: opts =>
            {
                opts.Backchannel = new HttpClient(mockHandler.Object);
            },
            configureCustomDomains: cdOpts =>
            {
                cdOpts.DomainResolver = _ => Task.FromResult(string.Empty);
            });

        using var client = server.CreateClient();

        // Act & Assert — the startup filter middleware throws InvalidOperationException
        // before the OIDC redirect is ever reached
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
        ex.Message.Should().Contain("DomainResolver returned empty issuer");
    }
}
