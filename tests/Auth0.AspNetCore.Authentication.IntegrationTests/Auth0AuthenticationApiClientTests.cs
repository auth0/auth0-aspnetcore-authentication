using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.AuthenticationApi.Models.Mfa;

using FluentAssertions;
using Moq;
using Xunit;
using Models = Auth0.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class Auth0AuthenticationApiClientTests
{
    private readonly Mock<IAuthenticationApiClient> _mockAuthenticationApiClient;
    private readonly Auth0AuthenticationApiClient.Auth0AuthenticationApiClient _auth0AuthenticationApiClient;

    public Auth0AuthenticationApiClientTests()
    {
        _mockAuthenticationApiClient = new Mock<IAuthenticationApiClient>();
        _auth0AuthenticationApiClient = new Auth0AuthenticationApiClient.Auth0AuthenticationApiClient(_mockAuthenticationApiClient.Object);
    }

    [Fact]
    public void Constructor_When_AuthenticationApiClient_Is_Null_Throws_ArgumentNullException()
    {
        var act = () => new Auth0AuthenticationApiClient.Auth0AuthenticationApiClient(null);

        act.Should().Throw<ArgumentNullException>()
            .And.ParamName.Should().Be("authenticationApiClient");
    }

    [Fact]
    public void Constructor_When_AuthenticationApiClient_Is_Valid_Creates_Instance()
    {
        var result = new Auth0AuthenticationApiClient.Auth0AuthenticationApiClient(_mockAuthenticationApiClient.Object);

        result.Should().NotBeNull();
    }

    [Fact]
    public void Dispose_Calls_Dispose_On_Underlying_Client()
    {
        _auth0AuthenticationApiClient.Dispose();
        _mockAuthenticationApiClient.Verify(x => x.Dispose(), Times.Once);
    }

    [Fact]
    public void BaseUri_Return_BaseUri_From_Underlying_Client()
    {
        var expectedUri = new Uri("https://example.auth0.com");
        _mockAuthenticationApiClient.Setup(x => x.BaseUri).Returns(expectedUri);

        var result = _auth0AuthenticationApiClient.BaseUri;

        result.Should().Be(expectedUri);
        _mockAuthenticationApiClient.Verify(x => x.BaseUri, Times.Once);
    }

    [Fact]
    public async Task ChangePasswordAsync_Calls_Underlying_Client_With_Request()
    {
        var request = new ChangePasswordRequest();
        var expectedResult = "password-changed";
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.ChangePasswordAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.ChangePasswordAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.ChangePasswordAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task ChangePasswordAsync_With_Default_CancellationToken_Calls_Underlying_Client()
    {
        var request = new ChangePasswordRequest();
        var expectedResult = "password-changed";
        _mockAuthenticationApiClient.Setup(
                x => x.ChangePasswordAsync(request, default))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.ChangePasswordAsync(request);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.ChangePasswordAsync(request, default), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_With_AuthorizationCodeTokenRequest_Calls_Underlying_Client()
    {
        var request = new AuthorizationCodeTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_WithAuthorizationCodePkceTokenRequest_Calls_Underlying_Client()
    {
        var request = new AuthorizationCodePkceTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_With_ClientCredentialsTokenRequest_Calls_Underlying_Client()
    {
        var request = new ClientCredentialsTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_With_RefreshTokenRequest_Calls_Underlying_Client()
    {
        var request = new RefreshTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_With_PasswordlessEmailTokenRequest_Calls_Underlying_Client()
    {
        var request = new PasswordlessEmailTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_With_PasswordlessSmsTokenRequest_Calls_Underlying_Client()
    {
        var request = new PasswordlessSmsTokenRequest();
        var expectedResult = new Models.AccessTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task RevokeRefreshTokenAsync_Calls_Underlying_Client()
    {
        var request = new RevokeRefreshTokenRequest();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.RevokeRefreshTokenAsync(request, cancellationToken))
            .Returns(Task.CompletedTask);

        await _auth0AuthenticationApiClient.RevokeRefreshTokenAsync(request, cancellationToken);

        _mockAuthenticationApiClient.Verify(
            x => x.RevokeRefreshTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task SignupUserAsync_Calls_Underlying_Client()
    {
        var request = new SignupUserRequest();
        var expectedResult = new SignupUserResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.SignupUserAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.SignupUserAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.SignupUserAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task StartPasswordlessEmailFlowAsync_Calls_Underlying_Client()
    {
        var request = new PasswordlessEmailRequest();
        var expectedResult = new PasswordlessEmailResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.StartPasswordlessEmailFlowAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = 
            await _auth0AuthenticationApiClient.StartPasswordlessEmailFlowAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.StartPasswordlessEmailFlowAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task StartPasswordlessSmsFlowAsync_Calls_Underlying_Client()
    {
        var request = new PasswordlessSmsRequest();
        var expectedResult = new PasswordlessSmsResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.StartPasswordlessSmsFlowAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = 
            await _auth0AuthenticationApiClient.StartPasswordlessSmsFlowAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.StartPasswordlessSmsFlowAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task ClientInitiatedBackchannelAuthorization_Calls_Underlying_Client()
    {
        var request = new ClientInitiatedBackchannelAuthorizationRequest();
        var expectedResult = new ClientInitiatedBackchannelAuthorizationResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.ClientInitiatedBackchannelAuthorization(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = 
            await _auth0AuthenticationApiClient.ClientInitiatedBackchannelAuthorization(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.ClientInitiatedBackchannelAuthorization(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_WithClientInitiatedBackchannelAuthorizationTokenRequest_Calls_Underlying_Client()
    {
        var request = new ClientInitiatedBackchannelAuthorizationTokenRequest();
        var expectedResult = new ClientInitiatedBackchannelAuthorizationTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = 
            await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task AssociateMfaAuthenticatorAsync_Calls_Underlying_Client()
    {
        var request = new AssociateMfaAuthenticatorRequest();
        var expectedResult = new AssociateMfaAuthenticatorResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.AssociateMfaAuthenticatorAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = 
            await _auth0AuthenticationApiClient.AssociateMfaAuthenticatorAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.AssociateMfaAuthenticatorAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task ListMfaAuthenticatorsAsync_Calls_Underlying_Client()
    {
        var accessToken = "access-token";
        var expectedResult = new List<Authenticator>();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(
                x => x.ListMfaAuthenticatorsAsync(accessToken, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.ListMfaAuthenticatorsAsync(accessToken, cancellationToken);

        result.Should().BeEquivalentTo(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.ListMfaAuthenticatorsAsync(accessToken, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task DeleteMfaAuthenticatorAsync_Calls_Underlying_Client()
    {
        var request = new DeleteMfaAuthenticatorRequest();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.DeleteMfaAuthenticatorAsync(request, cancellationToken))
            .Returns(Task.CompletedTask);

        await _auth0AuthenticationApiClient.DeleteMfaAuthenticatorAsync(request, cancellationToken);

        _mockAuthenticationApiClient.Verify(
            x => x.DeleteMfaAuthenticatorAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_WithMfaOobTokenRequest_Calls_Underlying_Client()
    {
        var request = new MfaOobTokenRequest();
        var expectedResult = new MfaOobTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_WithMfaOtpTokenRequest_Calls_Underlying_Client()
    {
        var request = new MfaOtpTokenRequest();
        var expectedResult = new MfaOtpTokenResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task GetTokenAsync_WithMfaRecoveryCodeRequest_Calls_Underlying_Client()
    {
        var request = new MfaRecoveryCodeRequest();
        var expectedResult = new MfaRecoveryCodeResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.GetTokenAsync(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.GetTokenAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(
            x => x.GetTokenAsync(request, cancellationToken), Times.Once);
    }

    [Fact]
    public async Task MfaChallengeAsync_Calls_Underlying_Client()
    {
        var request = new MfaChallengeRequest();
        var expectedResult = new MfaChallengeResponse();
        var cancellationToken = new CancellationToken();
        _mockAuthenticationApiClient.Setup(x => x.MfaChallenge(request, cancellationToken))
            .ReturnsAsync(expectedResult);

        var result = await _auth0AuthenticationApiClient.MfaChallengeAsync(request, cancellationToken);

        result.Should().Be(expectedResult);
        _mockAuthenticationApiClient.Verify(x => x.MfaChallenge(request, cancellationToken), Times.Once);
    }
}