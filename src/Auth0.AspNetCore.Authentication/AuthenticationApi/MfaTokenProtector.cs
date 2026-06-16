using System;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <summary>
/// Encrypts the <see cref="MfaTokenContext"/> into the opaque blob handed to the application,
/// and decrypts it back inside the SDK when completing the MFA flow.
/// </summary>
internal interface IMfaTokenProtector
{
    /// <summary>Encrypts <paramref name="context"/> into an opaque, integrity-protected blob.</summary>
    string Protect(MfaTokenContext context);

    /// <summary>
    /// Decrypts a blob produced by <see cref="Protect"/>.
    /// </summary>
    /// <exception cref="MfaTokenExpiredException">The blob's 5-minute lifetime has passed.</exception>
    /// <exception cref="MfaTokenInvalidException">The blob was tampered with, malformed, or protected with a different key.</exception>
    MfaTokenContext Unprotect(string protectedToken);
}

/// <inheritdoc />
internal sealed class MfaTokenProtector : IMfaTokenProtector
{
    // Versioned so the wire format can change later without ambiguity.
    private const string ProtectorPurpose = "Auth0.AspNetCore.Authentication.MfaToken.v1";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly IDataProtector _protector;

    public MfaTokenProtector(IDataProtectionProvider dataProtectionProvider)
    {
        if (dataProtectionProvider == null) throw new ArgumentNullException(nameof(dataProtectionProvider));
        _protector = dataProtectionProvider.CreateProtector(ProtectorPurpose);
    }

    public string Protect(MfaTokenContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        if (context.ExpiresAtUnix <= 0)
        {
            context.ExpiresAtUnix = DateTimeOffset.UtcNow.Add(Lifetime).ToUnixTimeSeconds();
        }

        var json = JsonSerializer.Serialize(context);
        return _protector.Protect(json);
    }

    public MfaTokenContext Unprotect(string protectedToken)
    {
        if (string.IsNullOrEmpty(protectedToken)) throw new MfaTokenInvalidException();

        string json;
        try
        {
            json = _protector.Unprotect(protectedToken);
        }
        catch (CryptographicException)
        {
            throw new MfaTokenInvalidException();
        }
        catch (FormatException)
        {
            throw new MfaTokenInvalidException();
        }

        MfaTokenContext? context;
        try
        {
            context = JsonSerializer.Deserialize<MfaTokenContext>(json);
        }
        catch (JsonException)
        {
            throw new MfaTokenInvalidException();
        }

        if (context == null || string.IsNullOrEmpty(context.MfaToken))
        {
            throw new MfaTokenInvalidException();
        }

        if (context.ExpiresAtUnix <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            throw new MfaTokenExpiredException();
        }

        return context;
    }
}
