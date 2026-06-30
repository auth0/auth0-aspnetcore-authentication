using System;
using System.Text;
using System.Text.Json;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Best-effort decoder for the RFC 8693 <c>act</c> (actor) claim from an ID token's JWT payload.
    /// Performs no signature verification — the token comes directly from the Auth0 token endpoint
    /// over the backchannel TLS connection. Any malformed input yields <c>null</c>.
    /// </summary>
    internal static class ActClaimReader
    {
        public static ActClaim? TryRead(string? idToken)
        {
            if (string.IsNullOrEmpty(idToken))
            {
                return null;
            }

            try
            {
                var parts = idToken.Split('.');
                if (parts.Length != 3)
                {
                    return null;
                }

                var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
                using var document = JsonDocument.Parse(payloadJson);

                if (!document.RootElement.TryGetProperty("act", out var actElement) ||
                    actElement.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }

                return ReadActElement(actElement);
            }
            catch (Exception)
            {
                // Best-effort: a decode/parse hiccup must not fail an exchange the endpoint accepted.
                return null;
            }
        }

        private static ActClaim ReadActElement(JsonElement element)
        {
            var claim = new ActClaim();

            if (element.TryGetProperty("sub", out var subElement) &&
                subElement.ValueKind == JsonValueKind.String)
            {
                claim.Sub = subElement.GetString();
            }

            if (element.TryGetProperty("act", out var nestedElement) &&
                nestedElement.ValueKind == JsonValueKind.Object)
            {
                claim.Act = ReadActElement(nestedElement);
            }

            return claim;
        }

        private static byte[] Base64UrlDecode(string input)
        {
            var output = input.Replace('-', '+').Replace('_', '/');
            switch (output.Length % 4)
            {
                case 2: output += "=="; break;
                case 3: output += "="; break;
            }
            return Convert.FromBase64String(output);
        }
    }
}
