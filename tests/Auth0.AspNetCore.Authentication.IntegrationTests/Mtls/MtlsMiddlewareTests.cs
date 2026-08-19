using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.IntegrationTests.Utils;
using FluentAssertions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class MtlsMiddlewareTests
    {
        [Fact]
        public void WithMtls_Throws_When_HttpClient_Is_Null()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureMtls: mtls => { /* HttpClient left null */ });

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be("WithMtls requires an HttpClient configured with the client certificate.");
        }

        [Fact]
        public void WithMtls_Throws_When_Backchannel_Already_Set()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureOptions: options => options.Backchannel = new HttpClient(),
                configureMtls: mtls => mtls.HttpClient = new HttpClient());

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be(
                    "Backchannel cannot be set when WithMtls supplies an HttpClient. Configure a single HttpClient " +
                    "with both the client certificate and your transport settings, and pass it to WithMtls.");
        }

        [Fact]
        public void WithMtls_Throws_When_Client_Secret_Also_Set()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureOptions: options => options.ClientSecret = "secret",
                configureMtls: mtls => mtls.HttpClient = new HttpClient());

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be("mTLS cannot be combined with a client secret or client assertion; the certificate is the sole credential.");
        }

        [Fact]
        public void WithMtls_Throws_When_Client_Assertion_Also_Set()
        {
            var provider = new RSACryptoServiceProvider();
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureOptions: options =>
                {
                    options.ClientAssertionSecurityKey = new RsaSecurityKey(provider);
                    options.ClientAssertionSecurityKeyAlgorithm = SecurityAlgorithms.RsaSha256;
                },
                configureMtls: mtls => mtls.HttpClient = new HttpClient());

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be("mTLS cannot be combined with a client secret or client assertion; the certificate is the sole credential.");
        }

        [Fact]
        public void WithMtls_Throws_When_Called_After_WithAccessToken()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureOptions: options => options.ClientSecret = "temp-secret-for-ordering-test",
                configureWithAccessTokensOptions: at => at.Audience = "http://local.auth0",
                configureMtls: mtls => mtls.HttpClient = new HttpClient(),
                withMtlsAfterAccessToken: true);

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be("WithMtls must be called before WithAccessToken.");
        }

        [Fact]
        public void WithCustomDomains_Throws_When_Called_After_WithMtls()
        {
            // mTLS wraps the OpenIdConnect ConfigurationManager while custom domains replaces it, so the
            // custom-domains registration must come first. Calling WithMtls before WithCustomDomains
            // would discard the mTLS wrapper on the login/PAR path; the builder fails fast instead.
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureCustomDomains: cd => cd.DomainResolver = _ => Task.FromResult("tenant.eu.auth0.com"),
                configureMtls: mtls => mtls.HttpClient = new HttpClient(),
                withMtlsBeforeCustomDomains: true);

            act.Should().Throw<InvalidOperationException>()
                .Which.Message.Should().Be("WithCustomDomains must be called before WithMtls.");
        }

        [Fact]
        public void WithMtls_Succeeds_With_HttpClient_And_No_Secret()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureWithAccessTokensOptions: at => at.Audience = "http://local.auth0",
                configureMtls: mtls => mtls.HttpClient = new HttpClient());

            act.Should().NotThrow();
        }

        private const string CnfHeader = "eyJhbGciOiJSUzI1NiJ9";
        private const string CnfPayloadPresent = "eyJjbmYiOnsieDV0I1MyNTYiOiJhYmMifX0";
        private const string CnfPayloadAbsent = "eyJzdWIiOiJ1MSJ9";

        [Fact]
        public async Task Par_Request_Goes_To_Mtls_Alias_Without_Client_Secret()
        {
            HttpRequestMessage capturedPar = null;
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls.json")
                .MockJwks()
                .MockPAR("https://my-par-request-uri", me => { capturedPar = me; return true; })
                .Build();

            using var server = TestServerBuilder.CreateServer(
                configureOptions: opt => opt.UsePushedAuthorization = true,
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object));
            using var client = server.CreateClient();

            var response = await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");

            response.Headers.Location.AbsolutePath.Should().Be("/authorize");
            capturedPar.Should().NotBeNull();
            capturedPar.RequestUri!.Host.Should().Be("mtls.tenant.eu.auth0.com");
            var body = await capturedPar.Content!.ReadAsStringAsync();
            body.Should().NotContain("client_secret=");
        }

        [Fact]
        public async Task Code_Exchange_Warns_When_Access_Token_Not_Cnf_Bound()
        {
            await RunCodeExchange($"{CnfHeader}.{CnfPayloadAbsent}.sig", sink =>
                sink.Logs.Should().ContainSingle(l =>
                    l.Level == LogLevel.Warning &&
                    l.Message == Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector.Warning));
        }

        [Fact]
        public async Task Code_Exchange_Silent_When_Access_Token_Cnf_Bound()
        {
            await RunCodeExchange($"{CnfHeader}.{CnfPayloadPresent}.sig", sink =>
                sink.Logs.Should().NotContain(l =>
                    l.Level == LogLevel.Warning &&
                    l.Message == Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector.Warning));
        }

        // Drives a full login -> callback code exchange with mTLS enabled and the given access token,
        // then runs the caller's assertion against the captured logs.
        private async Task RunCodeExchange(string accessToken, Action<CapturingLoggerProvider> assert)
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var sink = new CapturingLoggerProvider();

            // Uses a discovery document that advertises a token_endpoint alias (but no PAR alias, so the
            // handler does not attempt PAR): under mTLS the config manager fails closed when the token
            // alias is absent, so the standard fixture would break the login redirect here.
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls_token_only.json")
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1"),
                    me => me.HasAuth0ClientHeader(), accessToken: accessToken)
                .Build();

            using var server = TestServerBuilder.CreateServer(
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object),
                loggerProvider: sink);
            using var client = server.CreateClient();

            var loginResponse = await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
            var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");
            var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);
            nonce = queryParameters["nonce"];
            var state = queryParameters["state"];

            var message = new HttpRequestMessage(HttpMethod.Get,
                $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");
            await client.SendAsync(message, setCookie.Value);

            assert(sink);
        }

        [Fact]
        public void WithMtls_Composes_With_WithCustomDomains()
        {
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls.json")
                .MockJwks()
                .Build();

            Func<TestServer> act = () => TestServerBuilder.CreateServer(
                configureCustomDomains: cd => cd.DomainResolver = _ => Task.FromResult("tenant.eu.auth0.com"),
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object),
                configureWithAccessTokensOptions: at => at.Audience = "http://local.auth0");

            act.Should().NotThrow();
        }

        [Fact]
        public async Task Par_Request_Under_Custom_Domains_Goes_To_Mtls_Alias()
        {
            // Verifies the mTLS ConfigurationManager wrapper actually survives composition with custom
            // domains (rather than merely not throwing at startup): the PAR request on the login path
            // must be routed to the per-domain mtls alias, which only happens if the mTLS post-configure
            // wrapped the custom-domains manager instead of being discarded by it.
            HttpRequestMessage capturedPar = null;
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls.json")
                .MockJwks()
                .MockPAR("https://my-par-request-uri", me => { capturedPar = me; return true; })
                .Build();

            using var server = TestServerBuilder.CreateServer(
                configureOptions: opt => opt.UsePushedAuthorization = true,
                configureCustomDomains: cd => cd.DomainResolver = _ => Task.FromResult("tenant.eu.auth0.com"),
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object));
            using var client = server.CreateClient();

            var response = await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");

            response.Headers.Location.AbsolutePath.Should().Be("/authorize");
            capturedPar.Should().NotBeNull();
            capturedPar.RequestUri!.Host.Should().Be("mtls.tenant.eu.auth0.com");
        }

        [Fact]
        public async Task Par_Under_Mtls_Fails_Closed_When_Only_Standard_Par_Endpoint_Advertised()
        {
            // mTLS + PAR enabled, and the tenant advertises the token_endpoint alias plus a *standard*
            // pushed_authorization_request_endpoint but no mtls PAR alias. The PAR request carries the
            // client certificate and no client_secret; the standard host does not do client-certificate
            // authentication and would reject it as invalid_client. The handler must fail closed with the
            // actionable alias-missing error instead of silently posting to the standard host.
            HttpRequestMessage capturedPar = null;
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls_token_alias_std_par.json")
                .MockJwks()
                .MockPAR("https://my-par-request-uri", me => { capturedPar = me; return true; })
                .Build();

            using var server = TestServerBuilder.CreateServer(
                configureOptions: opt => opt.UsePushedAuthorization = true,
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object));
            using var client = server.CreateClient();

            Func<Task> act = () => client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");

            (await act.Should().ThrowAsync<InvalidOperationException>())
                .Which.Message.Should().Contain("mtls_endpoint_aliases.pushed_authorization_request_endpoint");
            // The certificate-less request never reached the standard PAR host.
            capturedPar.Should().BeNull();
        }

        [Fact]
        public async Task Par_Under_Mtls_Fails_Closed_When_No_Par_Endpoint_Advertised()
        {
            // mTLS + PAR enabled, and the discovery document advertises the token_endpoint alias but no
            // PAR endpoint at all (neither alias nor standard). The handler must surface the actionable
            // mtls alias-missing error rather than the generic "no PAR endpoint found" message, so the
            // cause (aliases not enabled on the tenant) is clear.
            var handler = new OidcMockBuilder()
                .MockOpenIdConfig("wellknownconfig_with_mtls_token_only.json")
                .MockJwks()
                .Build();

            using var server = TestServerBuilder.CreateServer(
                configureOptions: opt => opt.UsePushedAuthorization = true,
                configureMtls: mtls => mtls.HttpClient = new HttpClient(handler.Object));
            using var client = server.CreateClient();

            Func<Task> act = () => client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");

            (await act.Should().ThrowAsync<InvalidOperationException>())
                .Which.Message.Should().Contain("mtls_endpoint_aliases.pushed_authorization_request_endpoint");
        }

        private string GenerateToken(int userId, string issuer, string audience, string nonce, string subject, string organization = null, bool expired = false, string extraAudience = null, string azp = null, DateTime? authTime = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            };

            if (subject != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Sub, subject));
            }

            if (extraAudience != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, extraAudience));
            }

            if (!string.IsNullOrWhiteSpace(organization))
            {
                var organizationClaim = organization.StartsWith("org_") ? "org_id" : "org_name";
                claims.Add(new Claim(organizationClaim, organization));
            }

            if (!string.IsNullOrWhiteSpace(nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            if (!string.IsNullOrWhiteSpace(azp))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Azp, azp));
            }

            if (authTime != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.AuthTime, EpochTime.GetIntDate(authTime.Value).ToString()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                NotBefore = expired ? DateTime.UtcNow.Subtract(new TimeSpan(0, 2, 0, 0)) : (DateTime?) null,
                Expires = expired ? DateTime.UtcNow.Subtract(new TimeSpan(0, 1, 0, 0)) : DateTime.UtcNow.AddDays(7),
                Issuer = issuer,
                Audience = audience,
                IssuedAt = null
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
