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

    /// <summary>
    /// The ID token, when the completed grant requested the <c>openid</c> scope.
    /// <para>
    /// The MFA verify grants answer with the same payload as the password grant, which includes
    /// <c>id_token</c>; without this property it was deserialized away. It is <c>null</c> whenever
    /// <c>openid</c> was not among the scopes bound to the originating request.
    /// </para>
    /// </summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; }
}
