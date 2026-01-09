using System;
using System.Text.RegularExpressions;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

using HttpContext = Microsoft.AspNetCore.Http.HttpContext;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// A custom implementation of the <see cref="ICookieManager"/> interface that scopes cookies 
/// to a domain resolved dynamically from the <see cref="HttpContext"/>.
/// </summary>
/// <remarks>
/// This cookie manager ensures that authentication cookies are scoped to specific Auth0 custom domains,
/// preventing cookie conflicts when multiple domains are used within the same application.
/// The domain must be set in the HttpContext via the Auth0CustomDomainStartupFilter middleware.
/// </remarks>
public class Auth0CustomDomainsCookieManager : ICookieManager
{
    private readonly ICookieManager _concreteCookieManager;
    private static readonly Regex InvalidCookieNameCharsRegex = new(@"[^a-zA-Z0-9\-_\.]", RegexOptions.Compiled);

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0CustomDomainsCookieManager"/> class.
    /// </summary>
    /// <param name="concreteCookieManager">The underlying cookie manager implementation.
    /// If null, defaults to <see cref="ChunkingCookieManager"/>.</param>
    public Auth0CustomDomainsCookieManager(ICookieManager? concreteCookieManager = null)
    {
        _concreteCookieManager = concreteCookieManager ?? new ChunkingCookieManager();
    }

    /// <summary>
    /// Retrieves a cookie value from the request, scoped to the resolved domain.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="key">The base key of the cookie.</param>
    /// <returns>The value of the cookie, or <c>null</c> if the cookie does not exist.</returns>
    public string? GetRequestCookie(HttpContext context, string key)
    {
        var domainScopedCookieName = GetDomainScopedCookieName(context, key);
        return _concreteCookieManager.GetRequestCookie(context, domainScopedCookieName);
    }

    /// <summary>
    /// Appends a cookie to the response, scoped to the resolved domain.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="key">The base key of the cookie.</param>
    /// <param name="value">The value of the cookie.</param>
    /// <param name="options">The options for the cookie.</param>
    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options)
    {
        var domainScopedCookieName = GetDomainScopedCookieName(context, key);
        _concreteCookieManager.AppendResponseCookie(context, domainScopedCookieName, value, options);
    }

    /// <summary>
    /// Deletes a cookie from the response, scoped to the resolved domain.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="key">The base key of the cookie.</param>
    /// <param name="options">The options for the cookie.</param>
    public void DeleteCookie(HttpContext context, string key, CookieOptions options)
    {
        var domainScopedCookieName = GetDomainScopedCookieName(context, key);
        _concreteCookieManager.DeleteCookie(context, domainScopedCookieName, options);
    }

    /// <summary>
    /// Generates a domain-scoped cookie name by appending the resolved domain to the base key.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="baseKey">The base key of the cookie.</param>
    /// <returns>The domain-scoped cookie name.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="context"/> or
    /// <paramref name="baseKey"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the resolved domain is not available in the <see cref="HttpContext"/>.
    /// This typically indicates that the Auth0CustomDomainStartupFilter middleware is not configured
    /// or the DomainResolver was not set.
    /// </exception>
    internal string GetDomainScopedCookieName(HttpContext context, string baseKey)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(baseKey);

        var resolvedDomain = context.GetResolvedDomain();

        if (string.IsNullOrWhiteSpace(resolvedDomain))
        {
            throw new InvalidOperationException(
                "Resolved domain is not available in the HttpContext. " +
                "Ensure that Auth0CustomDomainsOptions.DomainResolver is configured and the " +
                "Auth0CustomDomainStartupFilter middleware is properly registered.");
        }

        // Sanitize the domain to ensure it's safe for use in cookie names
        var sanitizedDomain = SanitizeDomainForCookieName(resolvedDomain);
        
        return $"{baseKey}.{sanitizedDomain}";
    }

    /// <summary>
    /// Sanitizes a domain string to ensure it's safe for use in cookie names.
    /// Removes or replaces characters that are not allowed in cookie names.
    /// </summary>
    /// <param name="domain">The domain string to sanitize.</param>
    /// <returns>A sanitized domain string safe for cookie names.</returns>
    internal static string SanitizeDomainForCookieName(string domain)
    {
        var sanitized = domain.Replace("https://", "").Replace("http://", "");
        sanitized = sanitized.TrimEnd('/');
        
        // Replace invalid characters with underscores (keeps alphanumerics, hyphens, underscores, and dots)
        sanitized = InvalidCookieNameCharsRegex.Replace(sanitized, "_");
        
        return sanitized;
    }
}