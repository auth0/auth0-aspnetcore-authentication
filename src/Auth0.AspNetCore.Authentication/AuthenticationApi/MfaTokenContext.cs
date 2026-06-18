using System.Text.Json.Serialization;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <summary>
/// The internal payload that is JSON-serialized and encrypted into the opaque blob exposed as
/// <see cref="MfaRequiredException.MfaToken"/>. Binds the raw <c>mfa_token</c> to the
/// audience/scope of the originating request and carries its own expiry.
/// </summary>
internal sealed class MfaTokenContext
{
    /// <summary>The raw <c>mfa_token</c> issued by Auth0. Never leaves the SDK in plaintext.</summary>
    [JsonPropertyName("mfa_token")]
    public string MfaToken { get; set; } = null!;

    /// <summary>The audience the original refresh targeted, replayed on the MFA grant.</summary>
    [JsonPropertyName("audience")]
    public string? Audience { get; set; }

    /// <summary>The merged scope the original refresh targeted, replayed on the MFA grant.</summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>The available MFA requirements parsed from the error body.</summary>
    [JsonPropertyName("mfa_requirements")]
    public MfaRequirements? MfaRequirements { get; set; }

    /// <summary>Unix-seconds expiry. Enforced on unprotect to give a 5-minute lifetime.</summary>
    [JsonPropertyName("exp")]
    public long ExpiresAtUnix { get; set; }
}
