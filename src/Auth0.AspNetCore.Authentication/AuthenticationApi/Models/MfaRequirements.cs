using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>
/// The factors/challenge types Auth0 reports as available in an <c>mfa_required</c> error,
/// surfaced via <see cref="MfaRequiredException.MfaRequirements"/>. Tolerant of missing or
/// unknown fields — Auth0's shape can evolve.
/// </summary>
public class MfaRequirements
{
    /// <summary>The challenges the user can satisfy to complete MFA.</summary>
    [JsonPropertyName("challenge")]
    public IList<MfaChallengeRequirement>? Challenge { get; set; }
}

/// <summary>A single available MFA challenge option.</summary>
public class MfaChallengeRequirement
{
    /// <summary>The challenge type, e.g. <c>otp</c> or <c>oob</c>.</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>For an <c>oob</c> challenge, the available out-of-band channels (e.g. <c>sms</c>, <c>voice</c>).</summary>
    [JsonPropertyName("oob_channels")]
    public IList<string>? OobChannels { get; set; }

    /// <summary>The authenticator this challenge targets, when reported.</summary>
    [JsonPropertyName("authenticator_id")]
    public string? AuthenticatorId { get; set; }
}
