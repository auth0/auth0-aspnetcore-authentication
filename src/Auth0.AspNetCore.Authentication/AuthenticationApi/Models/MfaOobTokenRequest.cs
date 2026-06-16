namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>Request to complete MFA using an out-of-band (OOB) code.</summary>
public class MfaOobTokenRequest
{
    /// <summary>The <c>mfa_token</c> received from the <c>mfa_required</c> error.</summary>
    public string MfaToken { get; set; } = null!;

    /// <summary>The <c>oob_code</c> received from the challenge request.</summary>
    public string OobCode { get; set; } = null!;

    /// <summary>A code used to bind the side channel with the main authentication channel.</summary>
    public string? BindingCode { get; set; }
}
