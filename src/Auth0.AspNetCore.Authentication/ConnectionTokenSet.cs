using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Represents a third-party (federated connection) access token retrieved for a
    /// specific connection and cached alongside the primary token in the session.
    /// </summary>
    internal class ConnectionTokenSet
    {
        /// <summary>
        /// The federated connection name the token was retrieved for (e.g. "google-oauth2").
        /// </summary>
        [JsonPropertyName("connection")]
        public string Connection { get; set; } = null!;

        /// <summary>
        /// The login hint the token was retrieved for, when supplied. Part of the cache key
        /// alongside <see cref="Connection"/> so tokens for different linked identities on the
        /// same connection are cached separately rather than overwriting one another.
        /// </summary>
        [JsonPropertyName("login_hint")]
        public string? LoginHint { get; set; }

        /// <summary>
        /// The federated connection access token.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = null!;

        /// <summary>
        /// Expiration time as a Unix timestamp (seconds).
        /// </summary>
        [JsonPropertyName("expires_at")]
        public long ExpiresAt { get; set; }

        /// <summary>
        /// The scopes granted for the connection token, when returned. Optional.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }
}
