using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>
/// Base class for token responses returned by the Auth0 Authentication API.
/// </summary>
public abstract class TokenBase
{
    /// <summary>The access token.</summary>
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    /// <summary>The type of token (typically <c>Bearer</c>).</summary>
    [JsonPropertyName("token_type")]
    public string? TokenType { get; set; }
}
