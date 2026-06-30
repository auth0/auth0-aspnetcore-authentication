namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Controls how rigorously the refreshed <c>id_token</c> is validated before its claims
    /// replace the <see cref="System.Security.Claims.ClaimsPrincipal"/> when
    /// <see cref="Auth0WebAppWithAccessTokenOptions.RebuildPrincipalOnRefresh"/> is enabled.
    /// </summary>
    public enum RefreshClaimsValidationType
    {
        /// <summary>
        /// Validate the refreshed <c>id_token</c> signature against the cached JWKS, plus
        /// issuer/audience and the SDK's business-rule checks (sub, iat, azp, org, auth_time).
        /// This is the default and the safe choice.
        /// </summary>
        Full,

        /// <summary>
        /// Skip signature validation (trusting the back-channel TLS exchange with the token
        /// endpoint), while still running the SDK's business-rule checks. Lower cost and lower
        /// fidelity than <see cref="Full"/>.
        /// </summary>
        SkipSignature
    }
}
