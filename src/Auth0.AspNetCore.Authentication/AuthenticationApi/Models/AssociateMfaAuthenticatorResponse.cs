using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

/// <summary>The response to associating (enrolling) a new MFA authenticator.</summary>
public class AssociateMfaAuthenticatorResponse
{
    /// <summary>The code used for out-of-band authentication.</summary>
    [JsonPropertyName("oob_code")]
    public string? OobCode { get; set; }

    /// <summary>The binding method used.</summary>
    [JsonPropertyName("binding_method")]
    public string? BindingMethod { get; set; }

    /// <summary>The type of authenticator added.</summary>
    [JsonPropertyName("authenticator_type")]
    public string? AuthenticatorType { get; set; }

    /// <summary>The OOB channel used.</summary>
    [JsonPropertyName("oob_channel")]
    public string? OobChannel { get; set; }

    /// <summary>The recovery codes generated for the user.</summary>
    [JsonPropertyName("recovery_codes")]
    public List<string>? RecoveryCodes { get; set; }

    /// <summary>The URI to generate a QR code for the authenticator.</summary>
    [JsonPropertyName("barcode_uri")]
    public string? BarcodeUri { get; set; }

    /// <summary>The secret to use for the OTP.</summary>
    [JsonPropertyName("secret")]
    public string? Secret { get; set; }
}
