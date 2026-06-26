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
        /// Finds the cached token for a connection, or <c>null</c> when none is present.
        /// </summary>
        public static ConnectionTokenSet? FindConnectionTokenSet(IEnumerable<ConnectionTokenSet>? sets, string connection)
        {
            return sets?.FirstOrDefault(set => set.Connection == connection);
        }

        /// <summary>
        /// Applies a freshly retrieved connection token to the collection: prunes expired
        /// entries first, then replaces the entry for the connection if present, otherwise
        /// appends a new one. Returns the updated list (a new list instance).
        /// </summary>
        public static List<ConnectionTokenSet> UpsertConnectionTokenSet(IEnumerable<ConnectionTokenSet>? sets, string connection, AccessTokenResponse response)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var result = sets?.Where(set => set.ExpiresAt > now).ToList() ?? new List<ConnectionTokenSet>();

            var entry = new ConnectionTokenSet
            {
                Connection = connection,
                AccessToken = response.AccessToken,
                ExpiresAt = now + response.ExpiresIn,
                Scope = response.Scope
            };

            var existing = result.FirstOrDefault(set => set.Connection == connection);
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
    }
}
