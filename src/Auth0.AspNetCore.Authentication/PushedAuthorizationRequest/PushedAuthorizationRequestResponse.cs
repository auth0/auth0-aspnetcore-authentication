using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.PushedAuthorizationRequest;

internal class PushedAuthorizationRequestResponse
{
    [JsonPropertyName("expires_in")] 
    public int ExpiresIn { get; set; }

    [JsonPropertyName("request_uri")] 
    public string RequestUri { get; set; } = string.Empty;
}