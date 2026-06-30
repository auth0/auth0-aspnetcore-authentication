using System;
using System.Collections.Generic;

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
        /// Optional per-audience default scopes, used when requesting access tokens for
        /// additional audiences (MRRT). When an audience is present in this map, its value
        /// is used as the default scope for that audience; otherwise <see cref="Scope"/> is used.
        /// </summary>
        public IReadOnlyDictionary<string, string>? ScopeByAudience { get; set; }

        /// <summary>
        /// Define whether or not Refresh Tokens should be used internally when the access token is expired.
        /// </summary>
        public bool UseRefreshTokens { get; set; }

        /// <summary>
        /// The amount of time before an access token expires during which it is treated as
        /// already expired, so that a refresh is triggered proactively rather than the token
        /// lapsing mid-request. Applies to both the primary (login-time) token and additional
        /// audience/scope tokens retrieved on demand (MRRT). Defaults to 60 seconds.
        /// </summary>
        public TimeSpan AccessTokenExpirationLeeway { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// When <c>true</c>, the <see cref="System.Security.Claims.ClaimsPrincipal"/> is rebuilt
        /// from the refreshed <c>id_token</c> after a successful primary token refresh, so
        /// <c>User.Claims</c> reflect current user information. Defaults to <c>false</c>, which
        /// preserves the historical behavior where claims are never updated on refresh.
        /// </summary>
        public bool RebuildPrincipalOnRefresh { get; set; } = false;

        /// <summary>
        /// Controls how rigorously the refreshed <c>id_token</c> is validated before its claims
        /// replace the principal. Only consulted when <see cref="RebuildPrincipalOnRefresh"/> is
        /// <c>true</c>. Defaults to <see cref="RefreshClaimsValidationType.Full"/>.
        /// </summary>
        public RefreshClaimsValidationType RefreshClaimsValidationType { get; set; } = RefreshClaimsValidationType.Full;

        /// <summary>
        /// Events allowing you to hook into specific moments in the Auth0 middleware.
        /// </summary>
        public Auth0WebAppWithAccessTokenEvents? Events { get; set; }
    }
}
