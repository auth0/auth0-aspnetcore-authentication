namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Class containing Auth0 specific constants used throughout the SDK
    /// </summary>
    public class Auth0Constants
    {
        /// <summary>
        /// The Authentication Scheme, used when configuring OpenIdConnect
        /// </summary>
        public static string AuthenticationScheme = "Auth0";

        /// <summary>
        /// The callback path to which Auth0 should redirect back, used when configuring OpenIdConnect
        /// </summary>
        internal static string DefaultCallbackPath = "/callback";

        /// <summary>
        /// Key used to store the resolved domain in the authentication properties.
        /// </summary>
        internal static readonly string ResolvedDomainKey = "auth0:resolved-domain";

        /// <summary>
        /// Name of the ID token claim carrying the upstream IdP session ceiling (Unix seconds).
        /// Emitted when the connection option <c>id_token_session_expiry_supported</c> is enabled.
        /// </summary>
        public static readonly string SessionExpiryClaim = "session_expiry";

        /// <summary>
        /// Key used to persist the <c>session_expiry</c> ceiling (Unix seconds) in the authentication
        /// properties, kept separate from the token entries so it survives refreshes untouched.
        /// </summary>
        internal static readonly string SessionExpiryItemKey = "auth0:session_expiry";

        /// <summary>
        /// Negative leeway (in seconds) applied when comparing against the <c>session_expiry</c>
        /// ceiling, to account for clock skew: the session is treated as expired slightly before
        /// the wall-clock ceiling, never after.
        /// </summary>
        internal static readonly long SessionExpiryLeewaySeconds = 30;

        /// <summary>
        /// Upper bound (exclusive) for a valid <c>session_expiry</c> value, in Unix seconds. A value
        /// at or above this is rejected and treated as "no ceiling": a millisecond value emitted by
        /// mistake would read as a date thousands of years out and silently switch off enforcement.
        /// No real seconds value is this large (10,000,000,000 seconds is the year 2286).
        /// </summary>
        internal static readonly long SessionExpiryMaxSeconds = 10_000_000_000;

        /// <summary>
        /// The <c>issued_token_type</c> value that identifies a response as carrying a
        /// Session Transfer Token (STT). Branch on this value — never on <c>token_type</c>,
        /// which is the informational <c>N_A</c> for STT responses.
        /// </summary>
        public static readonly string SessionTransferTokenType = "urn:auth0:params:oauth:token-type:session_transfer_token";

        /// <summary>
        /// The RFC 8693 token-type URI for an ID token. Used as the default
        /// <c>actor_token_type</c> when the actor is auto-sourced from the agent's session id_token.
        /// </summary>
        internal static readonly string IdTokenType = "urn:ietf:params:oauth:token-type:id_token";
    }
}
