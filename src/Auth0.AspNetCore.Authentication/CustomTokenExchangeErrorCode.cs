namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Machine-readable error codes carried on <see cref="CustomTokenExchangeException.Code"/>.
    /// Constant names are C#-idiomatic PascalCase; values are the spec's snake_case, matching how
    /// nextjs-auth0 and auth0-server-python represent them.
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
        /// for a session-transfer exchange. Documented; surfaced via the raw server error.</summary>
        public const string SetActorRequired = "setactor_required";

        /// <summary>The token endpoint rejected the exchange because session transfer is disabled
        /// for the client. Documented; surfaced via the raw server error.</summary>
        public const string SessionTransferDisabled = "session_transfer_disabled";
    }
}
