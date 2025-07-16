using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.AuthenticationApi.Models.Mfa;
using Models = Auth0.AuthenticationApi.Models;
using CancellationToken = System.Threading.CancellationToken;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <summary>
/// Encapsulates the <see cref="AuthenticationApi.IAuthenticationApiClient"/> to provide a strongly-typed interface for
/// Auth0 Authentication API related operations. 
/// </summary>
public interface IAuthenticationApiClient : IDisposable
{
    /// <inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.BaseUri"/>
    Uri BaseUri { get; }

    /// <inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.ChangePasswordAsync"/>
    Task<string> ChangePasswordAsync(Models.ChangePasswordRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.AuthorizationCodeTokenRequest, CancellationToken)" /> 
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.AuthorizationCodeTokenRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.AuthorizationCodePkceTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.AuthorizationCodePkceTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.ClientCredentialsTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.ClientCredentialsTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.RefreshTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.RefreshTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.PasswordlessEmailTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.PasswordlessEmailTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(Models.PasswordlessSmsTokenRequest, CancellationToken)" />
    Task<Models.AccessTokenResponse> GetTokenAsync(Models.PasswordlessSmsTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.RevokeRefreshTokenAsync" />
    Task RevokeRefreshTokenAsync(Models.RevokeRefreshTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.SignupUserAsync" />
    Task<Models.SignupUserResponse> SignupUserAsync(Models.SignupUserRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.StartPasswordlessEmailFlowAsync" />
    Task<Models.PasswordlessEmailResponse> StartPasswordlessEmailFlowAsync(
        Models.PasswordlessEmailRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.StartPasswordlessSmsFlowAsync" />
    Task<Models.PasswordlessSmsResponse> StartPasswordlessSmsFlowAsync(Models.PasswordlessSmsRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.ClientInitiatedBackchannelAuthorization" />
    Task<ClientInitiatedBackchannelAuthorizationResponse> ClientInitiatedBackchannelAuthorization(
        ClientInitiatedBackchannelAuthorizationRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(ClientInitiatedBackchannelAuthorizationTokenRequest, CancellationToken)" />
    Task<ClientInitiatedBackchannelAuthorizationTokenResponse> GetTokenAsync(
        ClientInitiatedBackchannelAuthorizationTokenRequest request, CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.AssociateMfaAuthenticatorAsync" />
    Task<AssociateMfaAuthenticatorResponse> AssociateMfaAuthenticatorAsync(AssociateMfaAuthenticatorRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.ListMfaAuthenticatorsAsync" />
    Task<IList<Authenticator>> ListMfaAuthenticatorsAsync(string accessToken,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.DeleteMfaAuthenticatorAsync" />
    Task DeleteMfaAuthenticatorAsync(DeleteMfaAuthenticatorRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(MfaOobTokenRequest, CancellationToken)" />
    Task<MfaOobTokenResponse> GetTokenAsync(MfaOobTokenRequest request, CancellationToken cancellationToken = default);

    /// <inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(MfaOtpTokenRequest, CancellationToken)" />
    Task<MfaOtpTokenResponse> GetTokenAsync(MfaOtpTokenRequest request, CancellationToken cancellationToken = default);

    ///  <inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.GetTokenAsync(MfaRecoveryCodeRequest, CancellationToken)" />
    Task<MfaRecoveryCodeResponse> GetTokenAsync(MfaRecoveryCodeRequest request,
        CancellationToken cancellationToken = default);

    ///<inheritdoc cref="AuthenticationApi.IAuthenticationApiClient.MfaChallenge" />
    Task<MfaChallengeResponse> MfaChallengeAsync(MfaChallengeRequest request, CancellationToken cancellationToken = default);
}