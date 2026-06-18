using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>Request to associate (enroll) a new MFA authenticator.</summary>
public class AssociateMfaAuthenticatorRequest
{
    /// <summary>
    /// The bearer token to authorize enrollment: an access token with the <c>enroll</c> scope,
    /// or the <c>mfa_token</c> from an <c>mfa_required</c> error when the user has no active
    /// authenticators. Sent as an <c>Authorization</c> header, not in the body.
    /// </summary>
    [JsonIgnore]
    public string Token { get; set; } = null!;

    /// <summary>The authenticator types supported by the client (e.g. <c>otp</c>, <c>oob</c>).</summary>
    [JsonPropertyName("authenticator_types")]
    public string[]? AuthenticatorTypes { get; set; }

    /// <summary>The OOB channels supported by the client. Required if <c>authenticator_types</c> includes <c>oob</c>.</summary>
    [JsonPropertyName("oob_channels")]
    public List<string>? OobChannels { get; set; }

    /// <summary>The phone number for SMS or Voice. Required if <c>oob_channels</c> includes <c>sms</c> or <c>voice</c>.</summary>
    [JsonPropertyName("phone_number")]
    public string? PhoneNumber { get; set; }
}
