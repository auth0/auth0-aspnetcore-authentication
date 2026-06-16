using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>An MFA authenticator associated with a user.</summary>
public class Authenticator
{
    /// <summary>The authenticator ID.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>The authenticator type (e.g. <c>otp</c>, <c>oob</c>, <c>recovery-code</c>).</summary>
    [JsonPropertyName("authenticator_type")]
    public string? AuthenticatorType { get; set; }

    /// <summary>The OOB channel, when applicable.</summary>
    [JsonPropertyName("oob_channel")]
    public string? OobChannel { get; set; }

    /// <summary>The authenticator name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Whether the authenticator is active.</summary>
    [JsonPropertyName("active")]
    public bool Active { get; set; }
}
