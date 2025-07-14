using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.AuthenticationApi.Models.Mfa;

using Models = Auth0.AuthenticationApi.Models;
using CancellationToken = System.Threading.CancellationToken;
using IAuthenticationApiClient = Auth0.AuthenticationApi.IAuthenticationApiClient;

namespace Auth0.AspNetCore.Authentication.Auth0AuthenticationApiClient;

/// <summary>
/// Encapsulates the <see cref="IAuthenticationApiClient"/> to provide a strongly-typed interface for
/// Auth0 Authentication API related operations. 
/// </summary>
public interface IAuth0AuthenticationApiClient : IDisposable
{
    /// <inheritdoc cref="IAuthenticationApiClient.BaseUri"/>
    Uri BaseUri { get; }

    /// <inheritdoc cref="IAuthenticationApiClient.ChangePasswordAsync"/>
    Task<string> ChangePasswordAsync(Models.ChangePasswordRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.AuthorizationCodeTokenRequest, CancellationToken)" /> 
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.AuthorizationCodeTokenRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.AuthorizationCodePkceTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.AuthorizationCodePkceTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.ClientCredentialsTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.ClientCredentialsTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.RefreshTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.RefreshTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.PasswordlessEmailTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.PasswordlessEmailTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(Models.PasswordlessSmsTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.PasswordlessSmsTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.RevokeRefreshTokenAsync" />
    Task RevokeRefreshTokenAsync(Models.RevokeRefreshTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.SignupUserAsync" />
    Task<Models.SignupUserResponse> SignupUserAsync(Models.SignupUserRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.StartPasswordlessEmailFlowAsync" />
    Task<Models.PasswordlessEmailResponse> StartPasswordlessEmailFlowAsync(
        Models.PasswordlessEmailRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.StartPasswordlessSmsFlowAsync" />
    Task<Models.PasswordlessSmsResponse> StartPasswordlessSmsFlowAsync(Models.PasswordlessSmsRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.ClientInitiatedBackchannelAuthorization" />
    Task<ClientInitiatedBackchannelAuthorizationResponse> ClientInitiatedBackchannelAuthorization(
        ClientInitiatedBackchannelAuthorizationRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(ClientInitiatedBackchannelAuthorizationTokenRequest, CancellationToken)" />
    Task<ClientInitiatedBackchannelAuthorizationTokenResponse> GetTokenAsync(
        ClientInitiatedBackchannelAuthorizationTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.AssociateMfaAuthenticatorAsync" />
    Task<AssociateMfaAuthenticatorResponse> AssociateMfaAuthenticatorAsync(AssociateMfaAuthenticatorRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.ListMfaAuthenticatorsAsync" />
    Task<IList<Authenticator>> ListMfaAuthenticatorsAsync(string accessToken,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.DeleteMfaAuthenticatorAsync" />
    Task DeleteMfaAuthenticatorAsync(DeleteMfaAuthenticatorRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(MfaOobTokenRequest, CancellationToken)" />
    Task<MfaOobTokenResponse> GetTokenAsync(MfaOobTokenRequest request, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(MfaOtpTokenRequest, CancellationToken)" />
    Task<MfaOtpTokenResponse> GetTokenAsync(MfaOtpTokenRequest request, CancellationToken cancellationToken = default);

    ///  <inheritdoc cref="IAuthenticationApiClient.GetTokenAsync(MfaRecoveryCodeRequest, CancellationToken)" />
    Task<MfaRecoveryCodeResponse> GetTokenAsync(MfaRecoveryCodeRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="IAuthenticationApiClient.MfaChallenge" />
    Task<MfaChallengeResponse> MfaChallengeAsync(MfaChallengeRequest request, CancellationToken cancellationToken = default);
}