using System;
using System.Collections.Generic;
using System.Linq;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Selects how <see cref="TokenSetHelpers.FindAccessTokenSet"/> compares scopes.
    /// </summary>
    internal enum ScopeMatchMode
    {
        /// <summary>
        /// Superset membership against the requested scope (falling back to the granted
        /// scope for older entries that never recorded it). Used on the read path so a
        /// request for "read" can be served by a cached "read write" token.
        /// </summary>
        RequestedScope,

        /// <summary>
        /// Strict set-equality against the granted scope. Used when deciding whether a
        /// freshly granted token should replace an existing entry.
        /// </summary>
        Granted
    }

    /// <summary>
    /// Pure helper functions for scope handling and access-token-set matching/merging.
    /// </summary>
    internal static class TokenSetHelpers
    {
        /// <summary>
        /// Splits a space-separated scope string into individual scopes, dropping empties.
        /// </summary>
        public static string[] ParseScopes(string? scopes)
        {
            if (string.IsNullOrWhiteSpace(scopes))
            {
                return Array.Empty<string>();
            }

            return scopes.Trim().Split(' ').Where(s => !string.IsNullOrEmpty(s)).ToArray();
        }

        /// <summary>
        /// Merges two scope strings into an order-preserving union (no sorting).
        /// </summary>
        public static string MergeScopes(string? baseScopes, string? additionalScopes)
        {
            var ordered = ParseScopes(baseScopes).Concat(ParseScopes(additionalScopes)).Distinct().ToList();
            return string.Join(" ", ordered);
        }

        /// <summary>
        /// Determines whether all <paramref name="requiredScopes"/> are present in
        /// <paramref name="scopes"/> (set membership). When <paramref name="strict"/> is true,
        /// the two scope sets must be exactly equal.
        /// </summary>
        public static bool CompareScopes(string? scopes, string? requiredScopes, bool strict = false)
        {
            if (scopes == requiredScopes)
            {
                return true;
            }

            if (string.IsNullOrEmpty(scopes) || string.IsNullOrEmpty(requiredScopes))
            {
                return false;
            }

            var scopesSet = new HashSet<string>(ParseScopes(scopes));
            var requiredSet = new HashSet<string>(ParseScopes(requiredScopes));

            var hasAll = requiredSet.All(scopesSet.Contains);

            if (strict)
            {
                return hasAll && scopesSet.Count == requiredSet.Count;
            }

            return hasAll;
        }

        /// <summary>
        /// Returns the default scope configured for an audience: the per-audience entry when
        /// present, otherwise the global default.
        /// </summary>
        public static string? GetScopeForAudience(string? scope, IReadOnlyDictionary<string, string>? scopeByAudience, string? audience)
        {
            if (scopeByAudience != null && audience != null && scopeByAudience.TryGetValue(audience, out var audienceScope))
            {
                return audienceScope;
            }

            return scope;
        }

        /// <summary>
        /// Merges the requested scope with the configured defaults for the audience.
        /// Order-preserving union of default scopes followed by requested scopes.
        /// </summary>
        public static string? MergeScopeWithDefaults(string? requestScope, string? audience, string? scope, IReadOnlyDictionary<string, string>? scopeByAudience)
        {
            var defaultScope = GetScopeForAudience(scope, scopeByAudience, audience);
            var merged = MergeScopes(defaultScope, requestScope);

            return string.IsNullOrEmpty(merged) ? null : merged;
        }

        /// <summary>
        /// Finds the best matching <see cref="AccessTokenSet"/> for an audience and scope:
        /// an exact match is preferred, otherwise the smallest superset.
        /// </summary>
        /// <param name="matchMode">
        /// <see cref="ScopeMatchMode.RequestedScope"/> compares against the requested scope
        /// (falling back to granted); <see cref="ScopeMatchMode.Granted"/> compares strictly
        /// against the granted scope.
        /// </param>
        public static AccessTokenSet? FindAccessTokenSet(IEnumerable<AccessTokenSet>? sets, string audience, string? scope, ScopeMatchMode matchMode = ScopeMatchMode.RequestedScope)
        {
            if (sets == null)
            {
                return null;
            }

            // Audience must match exactly; scope comparison depends on the mode:
            //  - Granted: strict set-equality against the granted scope (used when deciding
            //    whether a freshly granted token should replace an existing entry).
            //  - RequestedScope (default): superset membership against the requested scope,
            //    falling back to granted for older entries that never recorded it (used on the
            //    read path, so a request for "read" can be served by a cached "read write" token).
            var strict = matchMode == ScopeMatchMode.Granted;
            var matches = sets.Where(set =>
                set.Audience == audience &&
                CompareScopes(
                    strict ? set.Scope : (set.RequestedScope ?? set.Scope),
                    scope,
                    strict))
                .ToList();

            if (matches.Count == 0)
            {
                return null;
            }

            // When several tokens qualify, prefer the least-scoped one (smallest superset) so we
            // never hand back a more privileged token than the request needs.
            return matches
                .OrderBy(set => new HashSet<string>(ParseScopes(set.Scope)).Count)
                .First();
        }

        /// <summary>
        /// Applies a freshly retrieved token to the additional-token collection:
        /// <list type="number">
        /// <item>Match by requested scope; if found, replace when the access token changed.</item>
        /// <item>Else match strictly by granted scope and merge the requested scopes (union).</item>
        /// <item>Else append a new entry.</item>
        /// </list>
        /// Returns the updated list (a new list instance).
        /// </summary>
        public static List<AccessTokenSet> UpsertAccessTokenSet(IEnumerable<AccessTokenSet>? sets, string audience, string? requestedScope, AccessTokenResponse response)
        {
            var result = sets?.ToList() ?? new List<AccessTokenSet>();

            // Case 1: we've served this request before. Refresh the token in place,
            // skipping the write when the access token is unchanged.
            var sameRequest = FindAccessTokenSet(result, audience, requestedScope, ScopeMatchMode.RequestedScope);
            if (sameRequest != null)
            {
                if (sameRequest.AccessToken != response.AccessToken)
                {
                    Replace(result, sameRequest, Build(audience, requestedScope, response));
                }

                return result;
            }

            // Case 2: a different request resolved to a token we already hold (Auth0
            // granted the same scope set). Reuse that entry and widen its RequestedScope
            // so both requests now resolve here.
            var sameGrant = FindAccessTokenSet(result, audience, response.Scope, ScopeMatchMode.Granted);
            if (sameGrant != null)
            {
                var mergedRequested = MergeScopes(sameGrant.RequestedScope, requestedScope);
                Replace(result, sameGrant, Build(audience, mergedRequested, response));

                return result;
            }

            // Case 3: a brand-new audience/scope combination.
            result.Add(Build(audience, requestedScope, response));

            return result;
        }

        private static void Replace(List<AccessTokenSet> sets, AccessTokenSet existing, AccessTokenSet updated)
        {
            var index = sets.IndexOf(existing);
            sets[index] = updated;
        }

        private static AccessTokenSet Build(string audience, string? requestedScope, AccessTokenResponse response)
        {
            return new AccessTokenSet
            {
                AccessToken = response.AccessToken,
                ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + response.ExpiresIn,
                Audience = audience,
                Scope = response.Scope,
                RequestedScope = string.IsNullOrEmpty(requestedScope) ? null : requestedScope
            };
        }
    }
}
