using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>The token response from completing MFA with an OTP code.</summary>
public class MfaOtpTokenResponse : TokenBase
{
    /// <summary>The lifetime in seconds of the access token.</summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}
