using System.Collections.Generic;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// The result of a Custom Token Exchange. Carries the exchanged tokens. This method
    /// has no session side-effects — the caller decides what (if anything) to persist.
    /// </summary>
    public class CustomTokenExchangeResult
    {
        /// <summary>The access token issued by Auth0.</summary>
        public string AccessToken { get; set; } = null!;

        /// <summary>The ID token, when an <c>openid</c> scope was granted.</summary>
        public string? IdToken { get; set; }

        /// <summary>
        /// The refresh token, when <c>offline_access</c> was granted. Auth0 suppresses the refresh
        /// token in delegation flows (when <c>actor_token</c> is present), so this is often null then.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>Token lifetime in seconds.</summary>
        public int ExpiresIn { get; set; }

        /// <summary>The granted scopes, when returned.</summary>
        public string? Scope { get; set; }

        /// <summary>
        /// The <c>act</c> (actor) claim decoded from the returned ID token, present in
        /// delegation/impersonation flows (RFC 8693). Null when there is no ID token, no act
        /// claim, or the ID token could not be decoded.
        /// </summary>
        public ActClaim? Act { get; set; }
    }

    /// <summary>
    /// The <c>act</c> (actor) claim from an ID token issued via RFC 8693 delegation. The outermost
    /// <see cref="Sub"/> identifies the current actor; nested <see cref="Act"/> values are prior
    /// actors in the delegation chain and are informational only (RFC 8693).
    /// </summary>
    public class ActClaim
    {
        /// <summary>The subject identifier of the acting party.</summary>
        public string? Sub { get; set; }

        /// <summary>Nested actor claim representing a delegation chain.</summary>
        public ActClaim? Act { get; set; }
    }
}
