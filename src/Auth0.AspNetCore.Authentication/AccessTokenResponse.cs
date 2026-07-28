using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Represents an access token response.
    /// </summary>
    internal class AccessTokenResponse
    {
        /// <summary>
        /// Identifier token.
        /// </summary>
        [JsonPropertyName("id_token")]
        public string IdToken { get; set; } = null!;

        /// <summary>
        /// Expiration time in seconds.
        /// </summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Refresh token.
        /// </summary>
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = null!;

        /// <summary>
        /// Access token.
        /// </summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = null!;

        /// <summary>
        /// Space-separated scopes granted for the access token.
        /// </summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }

        /// <summary>
        /// The RFC 8693 <c>issued_token_type</c>. For a Session Transfer Token exchange this is
        /// <see cref="Auth0Constants.SessionTransferTokenType"/>. Null for ordinary exchanges.
        /// </summary>
        [JsonPropertyName("issued_token_type")]
        public string? IssuedTokenType { get; set; }

        /// <summary>
        /// The <c>token_type</c>; informational only (typically <c>Bearer</c> or <c>N_A</c> for STTs).
        /// </summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }
    }
}
