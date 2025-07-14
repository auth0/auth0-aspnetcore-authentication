using System.Linq;

using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

using Auth0.AspNetCore.Authentication.Auth0AuthenticationApiClient;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0WebAppAuthenticationBuilderTests
{
    [Fact]
    public void WithAuth0AuthenticationApiClient_Should_Register_IAuth0AuthenticationApiClient_As_Transient()
    {
        var services = new ServiceCollection();
        var options = new Auth0WebAppOptions { Domain = "test-domain.auth0.com" };
        var builder = new Auth0WebAppAuthenticationBuilder(services, options);

        builder.WithAuth0AuthenticationApiClient();

        var serviceDescriptor = services.FirstOrDefault(s => s.ServiceType == typeof(IAuth0AuthenticationApiClient));
        serviceDescriptor.Should().NotBeNull();
        serviceDescriptor?.Lifetime.Should().Be(ServiceLifetime.Transient);
    }

    [Fact]
    public void WithAuth0AuthenticationApiClient_Should_Return_Same_Builder_Instance()
    {
        var services = new ServiceCollection();
        var options = new Auth0WebAppOptions { Domain = "test-domain.auth0.com" };
        var builder = new Auth0WebAppAuthenticationBuilder(services, options);

        var result = builder.WithAuth0AuthenticationApiClient();

        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void WithAuth0AuthenticationApiClient_Should_Create_Client_With_Correct_Domain()
    {
        var services = new ServiceCollection();
        var options = new Auth0WebAppOptions { Domain = "test-domain.auth0.com" };
        services.AddSingleton(Options.Create(options));
        var builder = new Auth0WebAppAuthenticationBuilder(services, options);

        builder.WithAuth0AuthenticationApiClient();

        var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<IAuth0AuthenticationApiClient>();

        client.Should().NotBeNull();
        client.Should().BeOfType<Auth0AuthenticationApiClient.Auth0AuthenticationApiClient>();
    }

    [Fact]
    public void WithAuth0AuthenticationApiClient_When_Called_Multiple_Times_Should_Register_Service_Multiple_Times()
    {
        var services = new ServiceCollection();
        var options = new Auth0WebAppOptions { Domain = "test-domain.auth0.com" };
        var builder = new Auth0WebAppAuthenticationBuilder(services, options);

        builder.WithAuth0AuthenticationApiClient();
        builder.WithAuth0AuthenticationApiClient();

        var serviceDescriptors = services.Where(s => s.ServiceType == typeof(IAuth0AuthenticationApiClient));
        serviceDescriptors.Should().HaveCount(2);
    }
}