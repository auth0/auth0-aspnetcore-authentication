using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Moq;
using Moq.Protected;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class MtlsAuthenticationApiClientTests
    {
        private const string Domain = "tenant.eu.auth0.com";
        private const string MtlsHost = "mtls.tenant.eu.auth0.com";

        private static readonly IMfaTokenProtector Protector = new MfaTokenProtector(new EphemeralDataProtectionProvider());

        private static Auth0WebAppOptions MtlsOptions() =>
            new Auth0WebAppOptions { Domain = Domain, ClientId = "cid", UseMtls = true };

        private static string Blob(string rawToken) =>
            Protector.Protect(new MfaTokenContext
            {
                MfaToken = rawToken,
                ExpiresAtUnix = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
            });

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

        private static (Mock<HttpMessageHandler> Handler, List<HttpRequestMessage> Captured, List<string> Bodies) BuildHandler(string okJson)
        {
            var captured = new List<HttpRequestMessage>();
            var bodies = new List<string>();
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
                    ItExpr.Is<HttpRequestMessage>(m =>
                        m.RequestUri!.AbsolutePath.EndsWith("mfa/challenge") ||
                        m.RequestUri!.AbsolutePath.EndsWith("oauth/token") ||
                        m.RequestUri!.AbsolutePath.EndsWith("mfa/authenticators")),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((m, _) =>
                {
                    captured.Add(m);
                    bodies.Add(m.Content?.ReadAsStringAsync().Result ?? "");
                })
                .ReturnsAsync(() => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(okJson)
                });

            return (handler, captured, bodies);
        }

        [Fact]
        public async Task MfaChallenge_Routes_To_Mtls_Host_Without_Client_Secret()
        {
            var (handler, captured, bodies) = BuildHandler("{\"challenge_type\":\"oob\"}");
            var client = new AuthenticationApiClient(
                new HttpClient(handler.Object),
                new Uri($"https://{Domain}"),
                MtlsOptions(),
                Protector,
                ownsHttpClient: false,
                mtlsEndpointResolver: new Auth0MtlsEndpointResolver());

            await client.MfaChallengeAsync(new MfaChallengeRequest { MfaToken = Blob("mt"), ChallengeType = "oob" });

            var challengeIdx = captured.FindIndex(r => r.RequestUri!.AbsolutePath.EndsWith("mfa/challenge"));
            var challenge = captured[challengeIdx];
            challenge.RequestUri!.Host.Should().Be(MtlsHost);
            bodies[challengeIdx].Should().NotContain("client_secret=");
        }

        [Fact]
        public async Task MfaChallenge_Throws_When_Mtls_Enabled_But_Resolver_Missing()
        {
            // UseMtls is true but no resolver was supplied. The client-authenticated path must fail
            // loudly rather than route a certificate-less request to the standard host.
            var (handler, _, _) = BuildHandler("{\"challenge_type\":\"oob\"}");
            var client = new AuthenticationApiClient(
                new HttpClient(handler.Object),
                new Uri($"https://{Domain}"),
                MtlsOptions(),
                Protector,
                ownsHttpClient: false,
                mtlsEndpointResolver: null);

            Func<Task> act = () => client.MfaChallengeAsync(new MfaChallengeRequest { MfaToken = Blob("mt"), ChallengeType = "oob" });

            (await act.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Be(
                "mTLS is enabled but no mTLS endpoint resolver is available. Ensure the SDK was configured with WithMtls.");
        }

        [Fact]
        public async Task MfaAuthenticatorsList_Stays_On_Standard_Host()
        {
            var (handler, captured, bodies) = BuildHandler("[{\"id\":\"a1\",\"authenticator_type\":\"otp\",\"active\":true}]");
            var client = new AuthenticationApiClient(
                new HttpClient(handler.Object),
                new Uri($"https://{Domain}"),
                MtlsOptions(),
                Protector,
                ownsHttpClient: false,
                mtlsEndpointResolver: new Auth0MtlsEndpointResolver());

            await client.ListMfaAuthenticatorsAsync("access-token");

            var list = captured.Find(r => r.RequestUri!.AbsolutePath.EndsWith("mfa/authenticators"))!;
            list.RequestUri!.Host.Should().Be(Domain);
        }
    }
}
