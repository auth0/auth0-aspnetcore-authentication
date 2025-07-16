using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AuthenticationApi.Models;
using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.AuthenticationApi.Models.Mfa;
using Models = Auth0.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <inheritdoc cref="IAuthenticationApiClient"/>
public class AuthenticationApiClient : IAuthenticationApiClient
{
    private readonly Auth0.AuthenticationApi.IAuthenticationApiClient _authenticationApiClient;

    public AuthenticationApiClient(Auth0.AuthenticationApi.IAuthenticationApiClient authenticationApiClient)
    {
        _authenticationApiClient = authenticationApiClient ?? throw new ArgumentNullException(nameof(authenticationApiClient));
    }

    /// <inheritdoc />
    public void Dispose() => _authenticationApiClient.Dispose();

    /// <inheritdoc />
    public Uri BaseUri => _authenticationApiClient.BaseUri;

    /// <inheritdoc />
    public Task<string> ChangePasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.ChangePasswordAsync(request, cancellationToken);
    }
    
    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(AuthorizationCodeTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(AuthorizationCodePkceTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(ClientCredentialsTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(PasswordlessEmailTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Models.AccessTokenResponse> GetTokenAsync(PasswordlessSmsTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task RevokeRefreshTokenAsync(RevokeRefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.RevokeRefreshTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<SignupUserResponse> SignupUserAsync(SignupUserRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.SignupUserAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<PasswordlessEmailResponse> StartPasswordlessEmailFlowAsync(PasswordlessEmailRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.StartPasswordlessEmailFlowAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<PasswordlessSmsResponse> StartPasswordlessSmsFlowAsync(PasswordlessSmsRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.StartPasswordlessSmsFlowAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<ClientInitiatedBackchannelAuthorizationResponse> ClientInitiatedBackchannelAuthorization(ClientInitiatedBackchannelAuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.ClientInitiatedBackchannelAuthorization(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<ClientInitiatedBackchannelAuthorizationTokenResponse> GetTokenAsync(ClientInitiatedBackchannelAuthorizationTokenRequest request,
        CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<AssociateMfaAuthenticatorResponse> AssociateMfaAuthenticatorAsync(AssociateMfaAuthenticatorRequest request,
        CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.AssociateMfaAuthenticatorAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<IList<Authenticator>> ListMfaAuthenticatorsAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.ListMfaAuthenticatorsAsync(accessToken, cancellationToken);
    }

    /// <inheritdoc />
    public Task DeleteMfaAuthenticatorAsync(DeleteMfaAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.DeleteMfaAuthenticatorAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaOobTokenResponse> GetTokenAsync(MfaOobTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaOtpTokenResponse> GetTokenAsync(MfaOtpTokenRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaRecoveryCodeResponse> GetTokenAsync(MfaRecoveryCodeRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.GetTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaChallengeResponse> MfaChallengeAsync(MfaChallengeRequest request, CancellationToken cancellationToken = default)
    {
        return _authenticationApiClient.MfaChallenge(request, cancellationToken);
    }
}