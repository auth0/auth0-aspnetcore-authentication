using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <summary>
/// A client for the subset of Auth0 Authentication API endpoints needed to recover from an
/// <c>mfa_required</c> error: triggering an MFA challenge, completing MFA via the OTP / OOB /
/// recovery-code grants, and managing authenticators.
/// </summary>
/// <remarks>
/// This is implemented over System.Text.Json within this SDK. The interface name, registration
/// (<see cref="Auth0WebAppAuthenticationBuilder.WithAuthenticationApiClient"/>) and method
/// shapes intentionally mirror the planned <c>Auth0.AuthenticationApi</c> integration so that a
/// future swap to that package is invisible to consumers. The request/response types in
/// <c>Auth0.AspNetCore.Authentication.AuthenticationApi.Models</c> are this SDK's own and form a
/// permanent public contract.
/// </remarks>
public interface IAuthenticationApiClient : IDisposable
{
    /// <summary>The base URI of the Auth0 Authentication API (e.g. <c>https://your-domain.auth0.com</c>).</summary>
    Uri BaseUri { get; }

    /// <summary>Triggers an MFA challenge (OTP, SMS, voice, or push) for an <c>mfa_token</c>.</summary>
    Task<MfaChallengeResponse> MfaChallengeAsync(MfaChallengeRequest request, CancellationToken cancellationToken = default);

    /// <summary>Completes MFA using a one-time password (OTP) code.</summary>
    Task<MfaOtpTokenResponse> GetTokenAsync(MfaOtpTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>Completes MFA using an out-of-band (OOB) code.</summary>
    Task<MfaOobTokenResponse> GetTokenAsync(MfaOobTokenRequest request, CancellationToken cancellationToken = default);

    /// <summary>Completes MFA using a recovery code.</summary>
    Task<MfaRecoveryCodeResponse> GetTokenAsync(MfaRecoveryCodeRequest request, CancellationToken cancellationToken = default);

    /// <summary>Associates (enrolls) a new MFA authenticator.</summary>
    Task<AssociateMfaAuthenticatorResponse> AssociateMfaAuthenticatorAsync(AssociateMfaAuthenticatorRequest request, CancellationToken cancellationToken = default);

    /// <summary>Lists the MFA authenticators associated with the user identified by the access token.</summary>
    Task<IList<Authenticator>> ListMfaAuthenticatorsAsync(string accessToken, CancellationToken cancellationToken = default);

    /// <summary>Deletes an associated MFA authenticator by ID.</summary>
    Task DeleteMfaAuthenticatorAsync(DeleteMfaAuthenticatorRequest request, CancellationToken cancellationToken = default);
}
