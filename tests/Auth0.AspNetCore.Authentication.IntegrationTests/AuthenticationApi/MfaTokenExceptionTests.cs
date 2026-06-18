using System.Net;
using Auth0.AspNetCore.Authentication;
using Auth0.AspNetCore.Authentication.Exceptions;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class MfaTokenExceptionTests
    {
        [Fact]
        public void MfaTokenExpiredException_Is_ErrorApiException_WithApiError()
        {
            var ex = new MfaTokenExpiredException();

            ex.Should().BeAssignableTo<ErrorApiException>();
            ex.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            ex.ApiError!.Error.Should().Be("mfa_token_expired");
        }

        [Fact]
        public void MfaTokenInvalidException_Is_ErrorApiException_WithApiError()
        {
            var ex = new MfaTokenInvalidException();

            ex.Should().BeAssignableTo<ErrorApiException>();
            ex.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            ex.ApiError!.Error.Should().Be("mfa_token_invalid");
        }
    }
}
