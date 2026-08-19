using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class Auth0MtlsConfigurationManagerTests
    {
        private sealed class StubManager : IConfigurationManager<OpenIdConnectConfiguration>
        {
            private readonly OpenIdConnectConfiguration _config;
            public int Calls { get; private set; }
            public StubManager(OpenIdConnectConfiguration config) => _config = config;
            public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
            {
                Calls++;
                return Task.FromResult(_config);
            }
            public void RequestRefresh() { }
        }

        private static OpenIdConnectConfiguration ConfigWithAliases()
        {
            var config = new OpenIdConnectConfiguration
            {
                TokenEndpoint = "https://tenant.eu.auth0.com/oauth/token",
                PushedAuthorizationRequestEndpoint = "https://tenant.eu.auth0.com/oauth/par"
            };
            using var doc = JsonDocument.Parse(
                "{\"token_endpoint\":\"https://mtls.tenant.eu.auth0.com/oauth/token\"," +
                "\"pushed_authorization_request_endpoint\":\"https://mtls.tenant.eu.auth0.com/oauth/par\"}");
            config.AdditionalData["mtls_endpoint_aliases"] = doc.RootElement.Clone();
            return config;
        }

        [Fact]
        public async Task Rewrites_Endpoints_To_Mtls_Aliases()
        {
            var manager = new Auth0MtlsConfigurationManager(new StubManager(ConfigWithAliases()));

            var config = await manager.GetConfigurationAsync(CancellationToken.None);

            config.TokenEndpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/token");
            config.PushedAuthorizationRequestEndpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/par");
        }

        [Fact]
        public async Task Is_Idempotent_Across_Repeated_Calls()
        {
            var manager = new Auth0MtlsConfigurationManager(new StubManager(ConfigWithAliases()));

            await manager.GetConfigurationAsync(CancellationToken.None);
            var config = await manager.GetConfigurationAsync(CancellationToken.None);

            config.TokenEndpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/token");
        }

        [Fact]
        public async Task Throws_When_Token_Endpoint_Alias_Absent()
        {
            // Fail-closed: the code exchange cannot fall back to the standard host under mTLS, so a
            // missing token_endpoint alias must raise the same actionable error the back-channel
            // resolver raises rather than silently leaving the standard endpoint in place.
            var inner = new OpenIdConnectConfiguration { TokenEndpoint = "https://tenant.eu.auth0.com/oauth/token" };
            var manager = new Auth0MtlsConfigurationManager(new StubManager(inner));

            Func<Task> act = () => manager.GetConfigurationAsync(CancellationToken.None);

            (await act.Should().ThrowAsync<InvalidOperationException>()).Which.Message.Should().Be(
                "mTLS is enabled but the authorization server discovery document does not advertise " +
                "`mtls_endpoint_aliases.token_endpoint`. Ensure mTLS endpoint aliases are enabled on your Auth0 tenant.");
        }

        [Fact]
        public async Task Rewrites_Token_Endpoint_And_Leaves_Par_When_Only_Token_Alias_Present()
        {
            // PAR is optional: this rewrite runs on every configuration fetch, so a tenant that
            // advertises the token alias but not a PAR alias must not throw, and the PAR endpoint is
            // left as discovered.
            var config = new OpenIdConnectConfiguration
            {
                TokenEndpoint = "https://tenant.eu.auth0.com/oauth/token",
                PushedAuthorizationRequestEndpoint = "https://tenant.eu.auth0.com/oauth/par"
            };
            using var doc = JsonDocument.Parse(
                "{\"token_endpoint\":\"https://mtls.tenant.eu.auth0.com/oauth/token\"}");
            config.AdditionalData["mtls_endpoint_aliases"] = doc.RootElement.Clone();
            var manager = new Auth0MtlsConfigurationManager(new StubManager(config));

            var result = await manager.GetConfigurationAsync(CancellationToken.None);

            result.TokenEndpoint.Should().Be("https://mtls.tenant.eu.auth0.com/oauth/token");
            result.PushedAuthorizationRequestEndpoint.Should().Be("https://tenant.eu.auth0.com/oauth/par");
        }
    }
}
