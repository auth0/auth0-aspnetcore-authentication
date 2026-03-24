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
    }
}
