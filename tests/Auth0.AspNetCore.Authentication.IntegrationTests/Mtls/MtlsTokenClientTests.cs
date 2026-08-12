using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class MtlsTokenClientTests
    {
        private const string Domain = "tenant.eu.auth0.com";
        private const string MtlsHost = "mtls.tenant.eu.auth0.com";
        private const string Header = "eyJhbGciOiJSUzI1NiJ9";
        private const string PayloadNoCnf = "eyJzdWIiOiJ1MSJ9";
        private const string PayloadWithCnf = "eyJjbmYiOnsieDV0I1MyNTYiOiJhYmMifX0";

        // Builds a handler that serves discovery + jwks, and captures the token request.
        private static (Mock<HttpMessageHandler> Handler, System.Collections.Generic.List<HttpRequestMessage> TokenRequests, System.Collections.Generic.Dictionary<HttpRequestMessage, string> Bodies, string AccessTokenJwt) BuildHandler(string accessTokenJwt)
        {
            var tokenRequests = new System.Collections.Generic.List<HttpRequestMessage>();
            var bodies = new System.Collections.Generic.Dictionary<HttpRequestMessage, string>();
            var handler = new Mock<HttpMessageHandler>();

            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/openid-configuration")),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => Resource("wellknownconfig_with_mtls.json"));
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/jwks.json")),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => Resource("jwks.json"));
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath == "/oauth/token"),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((m, _) =>
                {
                    tokenRequests.Add(m);
                    bodies[m] = m.Content!.ReadAsStringAsync().Result;
                })
                .ReturnsAsync(() => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $"{{\"access_token\":\"{accessTokenJwt}\",\"token_type\":\"Bearer\",\"expires_in\":86400,\"id_token\":\"{Header}.{PayloadNoCnf}.sig\"}}")
                });

            return (handler, tokenRequests, bodies, accessTokenJwt);
        }

        private static HttpResponseMessage Resource(string resource)
        {
            var name = "Auth0.AspNetCore.Authentication.IntegrationTests." + resource;
            using var stream = typeof(Startup).Assembly.GetManifestResourceStream(name)!;
            using var reader = new System.IO.StreamReader(stream);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(reader.ReadToEnd(), System.Text.Encoding.UTF8, "application/json")
            };
        }

        private static Auth0WebAppOptions MtlsOptions() =>
            new Auth0WebAppOptions { Domain = Domain, ClientId = "cid", UseMtls = true };

        [Fact]
        public async Task Refresh_Routes_To_Mtls_Alias_And_Omits_Client_Secret()
        {
            var (handler, tokenRequests, bodies, _) = BuildHandler($"{Header}.{PayloadWithCnf}.sig");
            var httpClient = new HttpClient(handler.Object);
            var client = new TokenClient(httpClient, new Auth0MtlsEndpointResolver());

            var result = await client.Refresh(MtlsOptions(), "refresh-123");

            result.IsSuccess.Should().BeTrue();
            tokenRequests.Should().ContainSingle();
            tokenRequests[0].RequestUri!.Host.Should().Be(MtlsHost);
            bodies[tokenRequests[0]].Should().NotContain("client_secret=");
        }

        [Fact]
        public async Task FederatedConnectionExchange_Routes_To_Mtls_Alias_And_Omits_Client_Secret()
        {
            var (handler, tokenRequests, bodies, _) = BuildHandler($"{Header}.{PayloadWithCnf}.sig");
            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver());

            await client.ExchangeRefreshTokenForConnectionToken(MtlsOptions(), "refresh-123", "google-oauth2");

            tokenRequests.Should().ContainSingle();
            tokenRequests[0].RequestUri!.Host.Should().Be(MtlsHost);
            bodies[tokenRequests[0]].Should().NotContain("client_secret=");
        }

        [Fact]
        public async Task CustomTokenExchange_Routes_To_Mtls_Alias_And_Omits_Client_Secret()
        {
            var (handler, tokenRequests, bodies, _) = BuildHandler($"{Header}.{PayloadWithCnf}.sig");
            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver());

            await client.ExchangeCustomToken(MtlsOptions(), "subject-token", "urn:example:token-type");

            tokenRequests.Should().ContainSingle();
            tokenRequests[0].RequestUri!.Host.Should().Be(MtlsHost);
            bodies[tokenRequests[0]].Should().NotContain("client_secret=");
        }

        [Fact]
        public async Task Refresh_Without_Mtls_Uses_Standard_Host()
        {
            var (handler, tokenRequests, bodies, _) = BuildHandler($"{Header}.{PayloadWithCnf}.sig");
            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver());

            await client.Refresh(new Auth0WebAppOptions { Domain = Domain, ClientId = "cid", ClientSecret = "secret" }, "refresh-123");

            tokenRequests.Should().ContainSingle();
            tokenRequests[0].RequestUri!.Host.Should().Be(Domain);
            bodies[tokenRequests[0]].Should().Contain("client_secret=secret");
        }

        [Fact]
        public async Task Refresh_Warns_When_Token_Not_Cnf_Bound()
        {
            var (handler, _, _, _) = BuildHandler($"{Header}.{PayloadNoCnf}.sig");
            var sink = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(sink));
            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver(), new MtlsCnfInspector(factory));

            await client.Refresh(MtlsOptions(), "refresh-123");

            sink.Logs.Should().ContainSingle(l => l.Level == LogLevel.Warning && l.Message == MtlsCnfInspector.Warning);
        }

        [Fact]
        public async Task Refresh_Silent_When_Token_Is_Cnf_Bound()
        {
            var (handler, _, _, _) = BuildHandler($"{Header}.{PayloadWithCnf}.sig");
            var sink = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(sink));
            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver(), new MtlsCnfInspector(factory));

            await client.Refresh(MtlsOptions(), "refresh-123");

            sink.Logs.Should().BeEmpty();
        }

        [Fact]
        public async Task Invalid_Client_Error_Reaches_TokenRefreshResult_Under_Mtls()
        {
            var handler = new Mock<HttpMessageHandler>();
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/openid-configuration")),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => Resource("wellknownconfig_with_mtls.json"));
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath.Contains(".well-known/jwks.json")),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => Resource("jwks.json"));
            handler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.Is<HttpRequestMessage>(m => m.RequestUri!.AbsolutePath == "/oauth/token"),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("{\"error\":\"invalid_client\",\"error_description\":\"bad cert\"}")
                });

            var client = new TokenClient(new HttpClient(handler.Object), new Auth0MtlsEndpointResolver());
            var result = await client.Refresh(MtlsOptions(), "refresh-123");

            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Be("invalid_client");
            result.ErrorDescription.Should().Be("bad cert");
        }
    }
}
