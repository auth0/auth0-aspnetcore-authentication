namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>Request to complete MFA using a one-time password (OTP).</summary>
public class MfaOtpTokenRequest
{
    /// <summary>The <c>mfa_token</c> received from the <c>mfa_required</c> error.</summary>
    public string MfaToken { get; set; } = null!;

    /// <summary>The OTP code provided by the user.</summary>
    public string Otp { get; set; } = null!;
}
