using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Moq;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

using Auth0.AspNetCore.Authentication.ClientInitiatedBackChannelAuthentication;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.Core.Exceptions;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0CibaServiceTest
{
    private readonly IAuth0CibaService _auth0CibaService;
    private readonly Mock<IAuthenticationApiClient> _mockAuthenticationApiClient = new();

    public Auth0CibaServiceTest()
    {
        _auth0CibaService = new Auth0CibaService(_mockAuthenticationApiClient.Object, Options.Create(
            new Auth0WebAppOptions()
            {
                ClientId = "clientId",
                ClientSecret = "secret"
            }), new NullLogger<Auth0CibaService>());
    }

    [Fact]
    public async Task InitiateAuthenticationAsync_ReturnsCibaInitiationDetails_OnSuccessfulRequest()
    {
        // Arrange
        var request = new CibaInitiationRequest
        {
            Audience = "test-audience",
            LoginHint = new LoginHint { Format = "test-format", Issuer = "test-issuer", Subject = "test-subject" },
            Scope = "openid",
            RequestExpiry = 300,
            AdditionalProperties = null,
            BindingMessage = "test-binding-message"
        };

        var cibaResponse = new ClientInitiatedBackchannelAuthorizationResponse
        {
            AuthRequestId = "test-auth-request-id",
            ExpiresIn = 300,
            Interval = 5
        };

        _mockAuthenticationApiClient
            .Setup(client =>
                client.ClientInitiatedBackchannelAuthorization(
                    It.IsAny<ClientInitiatedBackchannelAuthorizationRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(cibaResponse);

        // Act
        var result = await _auth0CibaService.InitiateAuthenticationAsync(request);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccessful.Should().BeTrue();
        cibaResponse.Interval.Should().Be(result.Interval);
        cibaResponse.ExpiresIn.Should().Be(result.ExpiresIn);
        cibaResponse.AuthRequestId.Should().Be(result.AuthRequestId);
    }

    [Fact]
    public async Task InitiateAuthenticationAsync_ThrowsException_OnApiError()
    {
        // Arrange
        var request = new CibaInitiationRequest
        {
            Audience = "test-audience",
            LoginHint = new LoginHint { Format = "test-format", Issuer = "test-issuer", Subject = "test-subject" },
            Scope = "openid"
        };

        _mockAuthenticationApiClient
            .Setup(client =>
                client.ClientInitiatedBackchannelAuthorization(
                    It.IsAny<ClientInitiatedBackchannelAuthorizationRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("API error"));

        // Act & Assert
        await Assert.ThrowsAsync<Exception>(() => _auth0CibaService.InitiateAuthenticationAsync(request));
    }

    [Fact]
    public async Task PollForTokensAsync_ReturnsCibaCompletionDetails_OnSuccessfulTokenRetrieval()
    {
        // Arrange
        var initDetails = new CibaInitiationDetails
        {
            AuthRequestId = "test-auth-request-id",
            Interval = 5
        };

        var tokenResponse = new ClientInitiatedBackchannelAuthorizationTokenResponse
        {
            AccessToken = "test-access-token",
            IdToken = "test-id-token",
            TokenType = "Bearer",
            Scope = "openid",
            ExpiresIn = 3600,
            RefreshToken = "test-refresh-token"
        };

        _mockAuthenticationApiClient
            .Setup(client => client.GetTokenAsync(It.IsAny<ClientInitiatedBackchannelAuthorizationTokenRequest>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenResponse);

        // Act
        var result = await _auth0CibaService.PollForTokensAsync(initDetails);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccessful.Should().BeTrue();
        tokenResponse.AccessToken.Should().BeEquivalentTo(result.AccessToken);
        tokenResponse.IdToken.Should().BeEquivalentTo(result.IdToken);
        tokenResponse.TokenType.Should().BeEquivalentTo(result.TokenType);
        tokenResponse.Scope.Should().BeEquivalentTo(result.Scope);
        tokenResponse.ExpiresIn.Should().Be(result.ExpiresIn);
        tokenResponse.RefreshToken.Should().BeEquivalentTo(result.RefreshToken);
    }

    [Fact]
    public async Task PollForTokensAsync_ReturnsPendingStatus_OnAuthorizationPendingError()
    {
        // Arrange
        var initDetails = new CibaInitiationDetails
        {
            AuthRequestId = "test-auth-request-id",
            Interval = 1
        };

        _mockAuthenticationApiClient
            .SetupSequence(client =>
                client.GetTokenAsync(It.IsAny<ClientInitiatedBackchannelAuthorizationTokenRequest>(),
                    It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ErrorApiException(HttpStatusCode.InternalServerError, new ApiError
                { Error = "authorization_pending", Message = "Authorization is pending" }))
            .ReturnsAsync(new ClientInitiatedBackchannelAuthorizationTokenResponse()
            {
                AccessToken = "test-access-token",
                IdToken = "test-id-token",
                TokenType = "Bearer",
                Scope = "openid",
                ExpiresIn = 3600
            });

        // Act
        var result = await _auth0CibaService.PollForTokensAsync(initDetails);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccessful.Should().BeTrue();
        result.AccessToken.Should().Be("test-access-token");
    }

    [Fact]
    public async Task PollForTokensAsync_ReturnsErrorDetails_OnNonPendingError()
    {
        // Arrange
        var initDetails = new CibaInitiationDetails
        {
            AuthRequestId = "test-auth-request-id",
            Interval = 5
        };

        var apiError = new ApiError { Error = "invalid_request", Message = "Invalid request" };

        _mockAuthenticationApiClient
            .Setup(client => client.GetTokenAsync(It.IsAny<ClientInitiatedBackchannelAuthorizationTokenRequest>(),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new ErrorApiException(HttpStatusCode.InternalServerError, apiError));

        // Act
        var result = await _auth0CibaService.PollForTokensAsync(initDetails);

        // Assert
        result.Should().NotBeNull();
        result.IsSuccessful.Should().BeFalse();
        apiError.Error.Should().BeEquivalentTo(result.Error);
        apiError.Message.Should().BeEquivalentTo(result.ErrorMessage);
    }
}