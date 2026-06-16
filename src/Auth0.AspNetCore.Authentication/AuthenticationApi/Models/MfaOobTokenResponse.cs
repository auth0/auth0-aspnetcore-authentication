using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>The token response from completing MFA with an OOB code.</summary>
public class MfaOobTokenResponse : TokenBase
{
    /// <summary>The lifetime in seconds of the access token.</summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>The error code returned when the OOB exchange has not yet succeeded (e.g. <c>authorization_pending</c>).</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>The description of the error.</summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
