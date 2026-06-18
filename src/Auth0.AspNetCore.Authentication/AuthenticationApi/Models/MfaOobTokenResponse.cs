using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>
/// The token response from completing MFA with an OOB code.
/// <para>
/// OOB verification (push/SMS) is asynchronous: while the user has not yet approved the request,
/// Auth0 answers with <c>authorization_pending</c> or <c>slow_down</c>. Those are surfaced on
/// <see cref="Error"/>/<see cref="ErrorDescription"/> (with <see cref="TokenBase.AccessToken"/> null)
/// so the caller can poll; any other failure throws an
/// <see cref="Exceptions.ErrorApiException"/>. On success the token fields are populated and
/// <see cref="Error"/> is null.
/// </para>
/// </summary>
public class MfaOobTokenResponse : TokenBase
{
    /// <summary>The lifetime in seconds of the access token.</summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>The error code returned while the OOB exchange has not yet succeeded
    /// (<c>authorization_pending</c> or <c>slow_down</c>); <c>null</c> on success.</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>The human-readable description accompanying <see cref="Error"/>; <c>null</c> on success.</summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}
