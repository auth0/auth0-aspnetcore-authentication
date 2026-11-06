using System.Collections.Generic;
using System.Security.Claims;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class SessionIssuerTests
    {
        private static ClaimsPrincipal PrincipalWith(params Claim[] claims)
            => new ClaimsPrincipal(new ClaimsIdentity(claims, "Test"));

        [Fact]
        public void Get_Returns_Iss_Claim_When_Present()
        {
            var principal = PrincipalWith(
                new Claim("iss", "https://iss-claim.example.com/"),
                new Claim("sid", "sid", null, "https://sid-issuer.example.com/"));
            var items = new Dictionary<string, string?> { [Auth0Constants.ResolvedDomainKey] = "persisted.example.com" };

            SessionIssuer.Get(principal, items).Should().Be("https://iss-claim.example.com/");
        }

        [Fact]
        public void Get_Returns_Sid_Claim_Issuer_Before_Persisted_Domain()
        {
            var principal = PrincipalWith(new Claim("sid", "sid", null, "https://tenant1.auth0.com/"));
            var items = new Dictionary<string, string?> { [Auth0Constants.ResolvedDomainKey] = "TENANT1.auth0.com" };

            SessionIssuer.Get(principal, items).Should().Be("https://tenant1.auth0.com/");
        }

        [Fact]
        public void Get_Returns_Persisted_Domain_When_Claims_Carry_No_Issuer()
        {
            // A Claim created without an issuer gets ClaimsIdentity.DefaultIssuer ("LOCAL AUTHORITY").
            var principal = PrincipalWith(new Claim("sid", "sid"));
            var items = new Dictionary<string, string?> { [Auth0Constants.ResolvedDomainKey] = "tenant1.auth0.com" };

            SessionIssuer.Get(principal, items).Should().Be("tenant1.auth0.com");
        }

        [Fact]
        public void Get_Lowercases_Persisted_Domain()
        {
            var principal = PrincipalWith(new Claim("sid", "sid"));
            var items = new Dictionary<string, string?> { [Auth0Constants.ResolvedDomainKey] = "TENANT1.auth0.com" };

            SessionIssuer.Get(principal, items).Should().Be("tenant1.auth0.com");
        }

        [Fact]
        public void Get_Returns_Null_When_Session_Carries_No_Issuer()
        {
            var principal = PrincipalWith(new Claim("sid", "sid"));

            SessionIssuer.Get(principal, new Dictionary<string, string?>()).Should().BeNull();
            SessionIssuer.Get(principal, new Dictionary<string, string?> { [Auth0Constants.ResolvedDomainKey] = " " }).Should().BeNull();
            SessionIssuer.Get(null, null).Should().BeNull();
        }
    }
}
