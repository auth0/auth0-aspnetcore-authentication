using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// The outcome of a refresh-token exchange: either a successful <see cref="Response"/>
    /// or, on a failure, the status code and parsed error details from the body. Construct
    /// via <see cref="Success"/> or <see cref="Failure"/> so the two states stay mutually exclusive.
    /// </summary>
    internal class TokenRefreshResult
    {
        private TokenRefreshResult()
        {
        }

        /// <summary>The successful token response, or <c>null</c> when the exchange failed.</summary>
        public AccessTokenResponse? Response { get; private set; }

        /// <summary>The HTTP status code returned by the token endpoint when the exchange failed.</summary>
        public int? StatusCode { get; private set; }

        /// <summary>The <c>error</c> code from the token endpoint's error body, when present.</summary>
        public string? Error { get; private set; }

        /// <summary>The <c>error_description</c> from the token endpoint's error body, when present.</summary>
        public string? ErrorDescription { get; private set; }

        /// <summary>The <c>mfa_token</c> from an <c>mfa_required</c> error body, when present.</summary>
        public string? MfaToken { get; private set; }

        /// <summary>The <c>mfa_requirements</c> from an <c>mfa_required</c> error body, when present.</summary>
        public MfaRequirements? MfaRequirements { get; private set; }

        public bool IsSuccess => Response != null;

        public static TokenRefreshResult Success(AccessTokenResponse response) =>
            new TokenRefreshResult { Response = response };

        public static TokenRefreshResult Failure(int? statusCode, string? error = null, string? errorDescription = null, string? mfaToken = null, MfaRequirements? mfaRequirements = null) =>
            new TokenRefreshResult
            {
                StatusCode = statusCode,
                Error = error,
                ErrorDescription = errorDescription,
                MfaToken = mfaToken,
                MfaRequirements = mfaRequirements
            };
    }
}
