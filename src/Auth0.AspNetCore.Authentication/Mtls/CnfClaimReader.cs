using System;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Best-effort reader for the <c>cnf.x5t#S256</c> certificate-thumbprint confirmation
    /// claim in an access token's JWT payload. Performs no signature verification — the token comes
    /// directly from the Auth0 token endpoint over the backchannel TLS connection.
    /// </summary>
    internal static class CnfClaimReader
    {
        /// <summary>
        /// Reports whether an access token is certificate-bound.
        /// <list type="bullet">
        /// <item><c>true</c>: the token is a JWT carrying a non-empty <c>cnf.x5t#S256</c>.</item>
        /// <item><c>false</c>: the token is a JWT with no <c>cnf.x5t#S256</c> (not sender-constrained).</item>
        /// <item><c>null</c>: the token is not an inspectable JWT (opaque, empty, or unparseable);
        /// its binding cannot be determined and callers should stay silent.</item>
        /// </list>
        /// </summary>
        public static bool? HasThumbprintConfirmation(string? accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return null;
            }

            var parts = accessToken.Split('.');
            if (parts.Length != 3)
            {
                return null;
            }

            try
            {
                var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
                using var document = JsonDocument.Parse(payloadJson);

                if (document.RootElement.TryGetProperty("cnf", out var cnf) &&
                    cnf.ValueKind == JsonValueKind.Object &&
                    cnf.TryGetProperty("x5t#S256", out var thumbprint) &&
                    thumbprint.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrEmpty(thumbprint.GetString()))
                {
                    return true;
                }

                return false;
            }
            catch (Exception)
            {
                // Best-effort: a decode/parse hiccup must not fail an exchange the endpoint accepted.
                return null;
            }
        }
    }
}
