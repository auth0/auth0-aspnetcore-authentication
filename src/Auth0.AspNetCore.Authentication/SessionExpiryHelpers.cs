using Microsoft.AspNetCore.Authentication;
using System.Globalization;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Pure helpers for the upstream-IdP <c>session_expiry</c> ceiling. All comparisons are in
    /// integer Unix seconds; callers convert wall-clock time to seconds at the boundary and stay
    /// in seconds from there.
    /// </summary>
    internal static class SessionExpiryHelpers
    {
        /// <summary>
        /// Parses a raw <c>session_expiry</c> value (Unix seconds) into a <see cref="long"/>.
        /// Tolerant of a missing, empty, or malformed value: returns <c>false</c> rather than throwing,
        /// so a session with no (or an unreadable) ceiling falls through to existing behavior.
        /// </summary>
        public static bool TryParseCeiling(string? raw, out long seconds)
        {
            seconds = 0;

            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            // The claim is an integer number of seconds; parse via double to tolerate a
            // value serialized as "1712345678.0", matching how auth_time is read elsewhere.
            if (double.TryParse(raw, NumberStyles.Any, CultureInfo.InvariantCulture, out var parsed))
            {
                seconds = (long)parsed;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Returns whether the ceiling has been reached, applying the negative clock-skew leeway:
        /// the session is treated as expired slightly before the wall-clock ceiling, never after.
        /// </summary>
        public static bool IsExpired(long ceilingSeconds, long nowSeconds)
        {
            return nowSeconds >= ceilingSeconds - Auth0Constants.SessionExpiryLeewaySeconds;
        }

        /// <summary>
        /// Reads the persisted ceiling from the session's authentication properties.
        /// Returns <c>false</c> when the session has no persisted ceiling (a session created before
        /// this feature, or under a connection without the option enabled) — which must never be
        /// treated as expired.
        /// </summary>
        public static bool TryGetPersistedCeiling(AuthenticationProperties properties, out long seconds)
        {
            seconds = 0;

            return properties.Items.TryGetValue(Auth0Constants.SessionExpiryItemKey, out var raw)
                && TryParseCeiling(raw, out seconds);
        }

        /// <summary>
        /// The single revocation gate: whether the persisted <c>session_expiry</c> ceiling has been
        /// reached as of <paramref name="nowSeconds"/>. A session with no persisted ceiling is never
        /// expired by this gate (falls through to existing idle/absolute behavior).
        /// </summary>
        public static bool IsSessionExpired(AuthenticationProperties properties, long nowSeconds)
        {
            return TryGetPersistedCeiling(properties, out var ceiling) && IsExpired(ceiling, nowSeconds);
        }
    }
}
