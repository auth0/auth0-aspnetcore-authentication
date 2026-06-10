using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Represents an additional access token retrieved for a specific audience/scope
    /// combination, stored alongside the primary token in the session.
    /// </summary>
    internal class AccessTokenSet
    {
        /// <summary>
        /// The access token.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = null!;

        /// <summary>
        /// Expiration time as a Unix timestamp (seconds).
        /// </summary>
        [JsonPropertyName("expires_at")]
        public long ExpiresAt { get; set; }

        /// <summary>
        /// The audience the token was requested for.
        /// </summary>
        [JsonPropertyName("audience")]
        public string Audience { get; set; } = null!;

        /// <summary>
        /// The scopes actually granted by the authorization server.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// The scopes originally requested. Tracked separately from <see cref="Scope"/>
        /// so that future requests for a subset/superset resolve to the same entry.
        /// </summary>
        [JsonPropertyName("requested_scope")]
        public string? RequestedScope { get; set; }

        /// <summary>
        /// The token type (e.g. "Bearer"). Optional.
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }
}
