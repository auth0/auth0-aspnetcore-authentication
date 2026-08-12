using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Moq;
using Moq.Protected;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class Auth0MtlsEndpointResolverTests
    {
        private const string Domain = "tenant.eu.auth0.com";

        [Fact]
        public async Task Resolves_Aliased_Token_Endpoint_From_Discovery()
        {
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls.json")
                .MockJwks()
                .Build();

            var resolver = new Auth0MtlsEndpointResolver();
            var endpoint = await resolver.ResolveTokenEndpointAsync(Domain, new HttpClient(handler.Object));

            endpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/token");
        }

        [Fact]
        public async Task Resolves_Aliased_Par_Endpoint_From_Discovery()
        {
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls.json")
                .MockJwks()
                .Build();

            var resolver = new Auth0MtlsEndpointResolver();
            var endpoint = await resolver.ResolvePushedAuthorizationRequestEndpointAsync(Domain, new HttpClient(handler.Object));

            endpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/par");
        }

        [Fact]
        public async Task Throws_Actionable_Message_When_Alias_Absent()
        {
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls_no_aliases.json")
                .MockJwks()
                .Build();

            var resolver = new Auth0MtlsEndpointResolver();
            Func<Task> act = () => resolver.ResolveTokenEndpointAsync(Domain, new HttpClient(handler.Object));

            (await act.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Be(
                "mTLS is enabled but the authorization server discovery document does not advertise " +
                "`mtls_endpoint_aliases.token_endpoint`. Ensure mTLS endpoint aliases are enabled on your Auth0 tenant.");
        }

        [Fact]
        public async Task Caches_Discovery_Per_Domain()
        {
            var configCalls = 0;
            var handler = new Mock<HttpMessageHandler>();
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/openid-configuration")),
                    ItExpr.IsAny<CancellationToken>())
                .Callback(() => configCalls++)
                .ReturnsAsync(() => ResourceResponse("wellknownconfig_with_mtls.json"));
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/jwks.json")),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => ResourceResponse("jwks.json"));

            var resolver = new Auth0MtlsEndpointResolver();
            var client = new HttpClient(handler.Object);
            await resolver.ResolveTokenEndpointAsync(Domain, client);
            await resolver.ResolvePushedAuthorizationRequestEndpointAsync(Domain, client);

            configCalls.Should().Be(1);
        }

        private static System.Net.Http.HttpResponseMessage ResourceResponse(string resource)
        {
            var name = "Auth0.AspNetCore.Authentication.IntegrationTests." + resource;
            using var stream = typeof(Startup).Assembly.GetManifestResourceStream(name)!;
            using var reader = new System.IO.StreamReader(stream);
            return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new System.Net.Http.StringContent(reader.ReadToEnd(), System.Text.Encoding.UTF8, "application/json")
            };
        }
    }
}
