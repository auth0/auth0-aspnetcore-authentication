namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Describes a Custom Token Exchange request: exchanging an external/custom
    /// security token for Auth0 tokens, without a browser redirect.
    /// </summary>
    public class CustomTokenExchangeRequest
    {
        /// <summary>
        /// The external token to exchange. Validated by your Auth0 Action with the Custom Token
        /// Exchange trigger. Required; must not be empty/whitespace and must not include a
        /// <c>"Bearer "</c> prefix.
        /// </summary>
        public string SubjectToken { get; set; } = null!;

        /// <summary>
        /// A custom URI identifying the subject token type, used as the routing key to select a
        /// Custom Token Exchange Profile. Required. The token endpoint validates the value against
        /// your configured profile.
        /// </summary>
        public string SubjectTokenType { get; set; } = null!;

        /// <summary>The unique identifier of the target API. Optional.</summary>
        public string? Audience { get; set; }

        /// <summary>Space-delimited OAuth 2.0 scopes. Optional.</summary>
        public string? Scope { get; set; }

        /// <summary>
        /// Actor token for delegation/impersonation. If set, <see cref="ActorTokenType"/>
        /// is required.
        /// </summary>
        public string? ActorToken { get; set; }

        /// <summary>
        /// Actor token type URI. Required when <see cref="ActorToken"/> is set.
        /// </summary>
        public string? ActorTokenType { get; set; }

        /// <summary>Organization ID or name for multi-tenant scenarios. Optional.</summary>
        public string? Organization { get; set; }
    }
}
