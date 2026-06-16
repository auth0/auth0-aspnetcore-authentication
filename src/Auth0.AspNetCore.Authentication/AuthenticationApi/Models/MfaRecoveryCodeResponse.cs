using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>The token response from completing MFA with a recovery code.</summary>
public class MfaRecoveryCodeResponse : TokenBase
{
    /// <summary>The lifetime in seconds of the access token.</summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>A new recovery code to store securely, replacing the one just used.</summary>
    [JsonPropertyName("recovery_code")]
    public string? RecoveryCode { get; set; }
}
