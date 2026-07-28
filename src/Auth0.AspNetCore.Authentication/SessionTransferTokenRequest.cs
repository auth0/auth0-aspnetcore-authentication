namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Describes a request for a Session Transfer Token (STT): a Custom Token Exchange that yields
    /// a short-lived, single-use handle for redirecting an agent's browser into a target app as the
    /// customer. The audience is set by the SDK to <c>urn:{resolved-domain}:session_transfer</c>;
    /// there is deliberately no <c>Audience</c> property.
    /// </summary>
    public class SessionTransferTokenRequest
    {
        /// <summary>
        /// The external/customer token to exchange (the impersonation subject). Required; opaque to
        /// the SDK. Must not be empty/whitespace and must not include a <c>"Bearer "</c> prefix.
        /// </summary>
        public string SubjectToken { get; set; } = null!;

        /// <summary>
        /// A custom URI identifying the subject token type; routes to the Custom Token Exchange
        /// Profile. Required.
        /// </summary>
        public string SubjectTokenType { get; set; } = null!;

        /// <summary>
        /// Optional explicit actor token (the agent). When omitted, the actor is auto-sourced from
        /// the current session's id_token. When supplied, it must be non-blank.
        /// </summary>
        public string? ActorToken { get; set; }

        /// <summary>
        /// Actor token type URI. Paired with <see cref="ActorToken"/>; defaults to the id_token URI
        /// (<see cref="Auth0Constants.IdTokenType"/>) when an actor is auto-sourced.
        /// </summary>
        public string? ActorTokenType { get; set; }

        /// <summary>Organization ID or name for multi-tenant scenarios. Optional.</summary>
        public string? Organization { get; set; }

        /// <summary>Space-delimited OAuth 2.0 scopes. Optional.</summary>
        public string? Scope { get; set; }
    }
}
