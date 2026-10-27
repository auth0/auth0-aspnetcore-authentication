using System.Collections.Generic;
using System.Security.Claims;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Resolves the issuer an authenticated session was established with, using only data carried
    /// in the protected authentication ticket. Unlike the per-request resolved domain, this cannot
    /// be influenced by the incoming request (e.g. the Host header).
    /// </summary>
    internal static class SessionIssuer
    {
        /// <summary>
        /// Returns the issuer bound to the session, or <c>null</c> when the ticket carries none.
        /// Sources, in order:
        /// <list type="bullet">
        ///   <item>an <c>iss</c> claim, when the application has opted to keep it on the principal;</item>
        ///   <item>the issuer recorded on the ID token's <c>sid</c> claim, i.e. the exact <c>iss</c>
        ///     of the validated ID token;</item>
        ///   <item>the domain persisted at login under <see cref="Auth0Constants.ResolvedDomainKey"/>
        ///     (multiple custom domains), for principals whose claims carry no issuer.</item>
        /// </list>
        /// </summary>
        public static string? Get(ClaimsPrincipal? principal, IDictionary<string, string?>? items)
        {
            var issClaim = principal?.FindFirst("iss")?.Value;
            if (!string.IsNullOrWhiteSpace(issClaim))
            {
                return issClaim;
            }

            var sidIssuer = principal?.FindFirst("sid")?.Issuer;
            if (!string.IsNullOrWhiteSpace(sidIssuer) && sidIssuer != ClaimsIdentity.DefaultIssuer)
            {
                return sidIssuer;
            }

            if (items != null &&
                items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var resolvedDomain) &&
                !string.IsNullOrWhiteSpace(resolvedDomain))
            {
                return resolvedDomain;
            }

            return null;
        }
    }
}
