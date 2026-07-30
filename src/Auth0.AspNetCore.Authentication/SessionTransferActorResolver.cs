using System;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Resolves the actor token for a Session Transfer Token exchange.
    /// An explicit actor wins; otherwise the caller sources the session id_token and, if stale,
    /// refreshes it.
    /// </summary>
    internal static class SessionTransferActorResolver
    {
        /// <summary>
        /// Validates and normalizes an explicit actor token supplied on the request.
        /// A blank/whitespace-only token, one carrying leading or trailing whitespace, or a
        /// <c>"Bearer "</c>-prefixed one throws <see cref="CustomTokenExchangeException"/> with
        /// <see cref="CustomTokenExchangeErrorCode.InvalidTokenFormat"/>.
        /// Returns the token paired with its type, defaulting the type to
        /// <see cref="Auth0Constants.IdTokenType"/> when not supplied.
        /// </summary>
        public static (string ActorToken, string ActorTokenType) ResolveExplicitActor(string actorToken, string? actorTokenType)
        {
            if (string.IsNullOrWhiteSpace(actorToken))
            {
                throw new CustomTokenExchangeException(
                    CustomTokenExchangeErrorCode.InvalidTokenFormat,
                    "actor_token was provided but is blank.");
            }

            if (actorToken != actorToken.Trim())
            {
                throw new CustomTokenExchangeException(
                    CustomTokenExchangeErrorCode.InvalidTokenFormat,
                    "actor_token must not include leading or trailing whitespace.");
            }

            if (actorToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                throw new CustomTokenExchangeException(
                    CustomTokenExchangeErrorCode.InvalidTokenFormat,
                    "actor_token must not include a \"Bearer \" prefix.");
            }

            return (actorToken, string.IsNullOrWhiteSpace(actorTokenType) ? Auth0Constants.IdTokenType : actorTokenType!);
        }

        /// <summary>
        /// Returns true when the id_token's own <c>exp</c> claim is beyond <c>now + leeway</c>.
        /// A malformed token, a missing/unparseable <c>exp</c>, or a decode failure yields false
        /// (treated as stale) so the caller falls through to a refresh.
        /// </summary>
        public static bool IsIdTokenFresh(string? idToken, TimeSpan leeway)
        {
            if (string.IsNullOrEmpty(idToken))
            {
                return false;
            }

            try
            {
                var parts = idToken.Split('.');
                if (parts.Length != 3)
                {
                    return false;
                }

                var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
                using var document = JsonDocument.Parse(payloadJson);

                if (!document.RootElement.TryGetProperty("exp", out var expElement) ||
                    !expElement.TryGetInt64(out var exp))
                {
                    return false;
                }

                var expiresAt = DateTimeOffset.FromUnixTimeSeconds(exp);
                return DateTimeOffset.Compare(expiresAt, DateTimeOffset.UtcNow.Add(leeway)) > 0;
            }
            catch (Exception)
            {
                // A decode/parse hiccup is treated as stale rather than throwing out of resolution.
                return false;
            }
        }
    }
}
