namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>
/// Request to trigger an MFA challenge for the authenticator(s) associated with an
/// <c>mfa_token</c> received from an <c>mfa_required</c> error.
/// </summary>
public class MfaChallengeRequest
{
    /// <summary>The <c>mfa_token</c> received from the <c>mfa_required</c> error.</summary>
    public string MfaToken { get; set; } = null!;

    /// <summary>A whitespace-separated list of challenge types accepted by your application.</summary>
    public string? ChallengeType { get; set; }

    /// <summary>The ID of the authenticator to challenge.</summary>
    public string? AuthenticatorId { get; set; }
}
