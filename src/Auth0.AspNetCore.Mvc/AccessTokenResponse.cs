using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Mvc
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
    }
}
