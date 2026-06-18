using Microsoft.AspNetCore.Http;
using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Provides the refreshed tokens to subscribers of
    /// <see cref="Auth0WebAppWithAccessTokenEvents.OnTokensRefreshed"/> after a successful
    /// primary token refresh. When <see cref="Auth0WebAppWithAccessTokenOptions.RebuildPrincipalOnRefresh"/>
    /// is enabled, the principal has already been rebuilt by the time this fires.
    /// </summary>
    public class AccessTokenRefreshedContext
    {
        private AccessTokenRefreshedContext(HttpContext httpContext, string accessToken, string idToken, string? refreshToken, DateTimeOffset expiresAt)
        {
            HttpContext = httpContext;
            AccessToken = accessToken;
            IdToken = idToken;
            RefreshToken = refreshToken;
            ExpiresAt = expiresAt;
        }

        internal static AccessTokenRefreshedContext Create(HttpContext httpContext, string accessToken, string idToken, string? refreshToken, DateTimeOffset expiresAt) =>
            new AccessTokenRefreshedContext(httpContext, accessToken, idToken, refreshToken, expiresAt);

        /// <summary>
        /// The current <see cref="HttpContext"/>, allowing you to resolve services or react to
        /// the successful refresh.
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// The refreshed access token.
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// The refreshed ID token.
        /// </summary>
        public string IdToken { get; }

        /// <summary>
        /// The rotated refresh token, when the token endpoint returned a new one;
        /// <c>null</c> when the refresh token was not rotated.
        /// </summary>
        public string? RefreshToken { get; }

        /// <summary>
        /// The absolute expiry of the refreshed access token.
        /// </summary>
        public DateTimeOffset ExpiresAt { get; }
    }
}
