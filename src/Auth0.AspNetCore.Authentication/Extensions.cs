using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication;

internal static class Extensions
{
    /// <summary>
    /// Retrieves the resolved domain from the <see cref="HttpContext.Items"/> collection.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <returns>
    /// The resolved domain as a <c>string</c> if present; otherwise, <c>null</c>.
    /// </returns>
    internal static string? GetResolvedDomain(this HttpContext httpContext)
    {
        return httpContext.Items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var domainObj)
            ? domainObj as string
            : null;
    }
}