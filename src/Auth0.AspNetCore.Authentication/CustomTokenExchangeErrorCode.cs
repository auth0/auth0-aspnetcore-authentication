namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Machine-readable error codes carried on <see cref="CustomTokenExchangeException.Code"/>.
    /// </summary>
    public static class CustomTokenExchangeErrorCode
    {
        /// <summary>No actor could be resolved (no explicit actor, no usable session id_token,
        /// no refreshable session). Raised client-side, before any network call.</summary>
        public const string ActorUnavailable = "actor_unavailable";

        /// <summary>An explicit actor token was supplied but was blank/whitespace-only.
        /// Raised client-side (matches the auth0-server-python PoC).</summary>
        public const string InvalidTokenFormat = "invalid_token_format";

        /// <summary>The token endpoint rejected the exchange because <c>setActor</c> is required
        /// for a session-transfer exchange.
        /// </summary>
        public const string SetActorRequired = "setactor_required";

        /// <summary>The token endpoint rejected the exchange because session transfer is disabled
        /// for the client.
        /// </summary>
        public const string SessionTransferDisabled = "session_transfer_disabled";

        /// <summary>
        /// Maps a token-endpoint <c>error</c> value onto one of the session-transfer codes,
        /// returning <c>null</c> when it is not one of them.
        /// </summary>
        internal static string? MapServerError(string? error) => error?.ToLowerInvariant() switch
        {
            SetActorRequired => SetActorRequired,
            SessionTransferDisabled => SessionTransferDisabled,
            _ => null
        };
    }
}
