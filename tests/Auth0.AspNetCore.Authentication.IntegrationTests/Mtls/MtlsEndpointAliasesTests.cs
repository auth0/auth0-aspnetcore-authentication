using System.Collections.Generic;
using System.Text.Json;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class MtlsEndpointAliasesTests
    {
        private static OpenIdConnectConfiguration WithAliases(string aliasesJson)
        {
            var config = new OpenIdConnectConfiguration();
            using var doc = JsonDocument.Parse(aliasesJson);
            config.AdditionalData["mtls_endpoint_aliases"] = doc.RootElement.Clone();
            return config;
        }

        [Fact]
        public void Returns_Aliased_Token_Endpoint_When_Present()
        {
            var config = WithAliases("{\"token_endpoint\":\"https://mtls.tenant.eu.auth0.com/oauth/token\"}");

            MtlsEndpointAliases.TryGetAlias(config, "token_endpoint")
                .Should().Be("https://mtls.tenant.eu.auth0.com/oauth/token");
        }

        [Fact]
        public void Returns_Null_When_Aliases_Absent()
        {
            var config = new OpenIdConnectConfiguration();

            MtlsEndpointAliases.TryGetAlias(config, "token_endpoint").Should().BeNull();
        }

        [Fact]
        public void Returns_Null_When_Requested_Endpoint_Absent()
        {
            var config = WithAliases("{\"token_endpoint\":\"https://mtls.tenant.eu.auth0.com/oauth/token\"}");

            MtlsEndpointAliases.TryGetAlias(config, "pushed_authorization_request_endpoint").Should().BeNull();
        }

        [Fact]
        public void Returns_Null_When_Aliases_Is_A_Scalar_String()
        {
            var config = new OpenIdConnectConfiguration();
            config.AdditionalData["mtls_endpoint_aliases"] = "not-an-object";

            MtlsEndpointAliases.TryGetAlias(config, "token_endpoint").Should().BeNull();
        }
    }
}
