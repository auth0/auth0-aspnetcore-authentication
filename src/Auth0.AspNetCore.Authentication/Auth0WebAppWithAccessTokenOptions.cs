namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Options used to configure the SDK when using Access Tokens
    /// </summary>
    public class Auth0WebAppWithAccessTokenOptions
    {
        /// <summary>
        /// The audience to be used for requesting API access.
        /// </summary>
        public string? Audience { get; set; }

        /// <summary>
        /// Scopes to be used to request token(s). (e.g. "Scope1 Scope2 Scope3")
        /// </summary>
        public string? Scope { get; set; }

        /// <summary>
        /// Define whether or not Refresh Tokens should be used internally when the access token is expired.
        /// </summary>
        public bool UseRefreshTokens { get; set; }

        /// <summary>
        /// Events allowing you to hook into specific moments in the Auth0 middleware.
        /// </summary>
        public Auth0WebAppWithAccessTokenEvents? Events { get; set; }
    }
}
