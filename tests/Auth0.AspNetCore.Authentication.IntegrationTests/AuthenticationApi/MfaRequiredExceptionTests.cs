using System.Net;
using Auth0.AspNetCore.Authentication;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using Auth0.AspNetCore.Authentication.Exceptions;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class MfaRequiredExceptionTests
    {
        [Fact]
        public void Constructor_WithRequirements_ExposesThem()
        {
            var requirements = new MfaRequirements
            {
                Challenge = new[] { new MfaChallengeRequirement { Type = "otp" } }
            };

            var ex = new MfaRequiredException("blob", requirements, HttpStatusCode.Forbidden,
                new ApiError { Error = "mfa_required" });

            ex.MfaToken.Should().Be("blob");
            ex.MfaRequirements.Should().BeSameAs(requirements);
            ex.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public void Constructor_WithoutRequirements_LeavesThemNull()
        {
            var ex = new MfaRequiredException("blob", HttpStatusCode.Forbidden);

            ex.MfaToken.Should().Be("blob");
            ex.MfaRequirements.Should().BeNull();
        }
    }
}
