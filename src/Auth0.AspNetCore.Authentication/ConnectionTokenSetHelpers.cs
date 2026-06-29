using System;
using System.Collections.Generic;
using System.Linq;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Pure helper functions for matching, upserting and pruning per-connection
    /// (federated connection) access tokens stored in the session.
    /// </summary>
    internal static class ConnectionTokenSetHelpers
    {
        /// <summary>
        /// Finds the cached token for a connection and login hint, or <c>null</c> when none is
        /// present. The login hint is part of the key: a request with a given hint only matches a
        /// cached entry stored for that same hint (a request with no hint matches an entry stored
        /// with no hint), so tokens for different linked identities on one connection don't collide.
        /// </summary>
        public static ConnectionTokenSet? FindConnectionTokenSet(IEnumerable<ConnectionTokenSet>? sets, string connection, string? loginHint = null)
        {
            return sets?.FirstOrDefault(set => Matches(set, connection, loginHint));
        }

        /// <summary>
        /// Applies a freshly retrieved connection token to the collection: prunes expired
        /// entries first, then replaces the entry for the connection and login hint if present,
        /// otherwise appends a new one. Returns the updated list (a new list instance).
        /// </summary>
        public static List<ConnectionTokenSet> UpsertConnectionTokenSet(IEnumerable<ConnectionTokenSet>? sets, string connection, AccessTokenResponse response, string? loginHint = null)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var result = sets?.Where(set => set.ExpiresAt > now).ToList() ?? new List<ConnectionTokenSet>();

            var entry = new ConnectionTokenSet
            {
                Connection = connection,
                LoginHint = loginHint,
                AccessToken = response.AccessToken,
                ExpiresAt = now + response.ExpiresIn,
                Scope = response.Scope
            };

            var existing = result.FirstOrDefault(set => Matches(set, connection, loginHint));
            if (existing != null)
            {
                result[result.IndexOf(existing)] = entry;
            }
            else
            {
                result.Add(entry);
            }

            return result;
        }

        private static bool Matches(ConnectionTokenSet set, string connection, string? loginHint)
        {
            return set.Connection == connection && set.LoginHint == loginHint;
        }
    }
}
