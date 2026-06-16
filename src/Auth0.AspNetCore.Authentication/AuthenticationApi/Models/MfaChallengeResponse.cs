using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>The response to an MFA challenge request.</summary>
public class MfaChallengeResponse
{
    /// <summary>The type of challenge issued.</summary>
    [JsonPropertyName("challenge_type")]
    public string? ChallengeType { get; set; }

    /// <summary>The code for an out-of-band challenge, when applicable.</summary>
    [JsonPropertyName("oob_code")]
    public string? OobCode { get; set; }

    /// <summary>The binding method, when applicable.</summary>
    [JsonPropertyName("binding_method")]
    public string? BindingMethod { get; set; }
}
