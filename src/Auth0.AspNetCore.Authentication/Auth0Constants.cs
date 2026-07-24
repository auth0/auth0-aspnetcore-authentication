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
    }
}
