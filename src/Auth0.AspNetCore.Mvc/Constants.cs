namespace Auth0.AspNetCore.Mvc
{
    public class Constants
    {
        /// <summary>
        /// The Authentication Scheme, used when configuring OpenIdConnect
        /// </summary>
        public static string AuthenticationScheme = "Auth0";

        /// <summary>
        /// The Issuer for the claims, used when configuring OpenIdConnect
        /// </summary>
        internal static string ClaimsIssuer = "Auth0";

        /// <summary>
        /// The callback path to which Auth0 should redirect back, used when configuring OpenIdConnect
        /// </summary>
        internal static string DefaultCallbackPath = "/callback";
    }
}
