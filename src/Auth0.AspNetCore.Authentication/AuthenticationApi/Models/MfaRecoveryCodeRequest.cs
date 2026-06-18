namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>Request to complete MFA using a recovery code.</summary>
public class MfaRecoveryCodeRequest
{
    /// <summary>The <c>mfa_token</c> received from the <c>mfa_required</c> error.</summary>
    public string MfaToken { get; set; } = null!;

    /// <summary>The recovery code provided by the user.</summary>
    public string RecoveryCode { get; set; } = null!;
}
