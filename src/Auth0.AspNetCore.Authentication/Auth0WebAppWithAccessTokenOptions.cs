using System;

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
        /// The amount of time before an access token expires during which it is treated as
        /// already expired, so that a refresh is triggered proactively rather than the token
        /// lapsing mid-request. Only applies when <see cref="UseRefreshTokens"/> is enabled.
        /// Defaults to 60 seconds.
        /// </summary>
        public TimeSpan AccessTokenExpirationLeeway { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Events allowing you to hook into specific moments in the Auth0 middleware.
        /// </summary>
        public Auth0WebAppWithAccessTokenEvents? Events { get; set; }
    }
}
