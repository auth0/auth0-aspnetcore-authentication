namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>Request to delete an associated MFA authenticator.</summary>
public class DeleteMfaAuthenticatorRequest
{
    /// <summary>An access token with scope <c>remove:authenticators</c> and the MFA audience.</summary>
    public string AccessToken { get; set; } = null!;

    /// <summary>The ID of the authenticator to delete.</summary>
    public string AuthenticatorId { get; set; } = null!;
}
