using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.CustomDomains;

/// <summary>
/// A custom implementation of <see cref="IConfigurationManager{OpenIdConnectConfiguration}"/> that maintains
/// separate OpenID Connect configurations per Auth0 custom domain.
/// </summary>
/// <remarks>
/// Resolves configurations dynamically based on the domain associated with each request,
/// enabling support for multiple Auth0 custom domains within a single application instance.
/// Each domain's configuration is cached independently using the provided <see cref="IConfigurationManagerCache"/>.
/// Registered as a singleton and maintain its cache throughout the application lifetime.
/// </remarks>
internal sealed class Auth0CustomDomainsOpenIdConnectConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>, IDisposable
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly Func<HttpContext, Task<string>> _domainResolver;
    private readonly ISecureDataFormat<AuthenticationProperties> _stateDataFormat;
    private readonly HttpClient _httpClient;
    private readonly IConfigurationManagerCache _cache;
    private readonly bool _ownsCache;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="Auth0CustomDomainsOpenIdConnectConfigurationManager"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">The HTTP context accessor for retrieving the current request context.</param>
    /// <param name="domainResolver">The function to resolve the Auth0 domain from the HTTP context.</param>
    /// <param name="stateDataFormat">The secure data format for protecting/unprotecting authentication state.</param>
    /// <param name="httpClient">The HTTP client for retrieving OpenID Connect configurations.</param>
    /// <param name="cache">
    /// The cache for configuration managers. If null, a default <see cref="MemoryConfigurationManagerCache"/> is used.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when any required parameter is null.</exception>
    public Auth0CustomDomainsOpenIdConnectConfigurationManager(
        IHttpContextAccessor httpContextAccessor,
        Func<HttpContext, Task<string>> domainResolver,
        ISecureDataFormat<AuthenticationProperties> stateDataFormat,
        HttpClient httpClient,
        IConfigurationManagerCache? cache = null)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _domainResolver = domainResolver ?? throw new ArgumentNullException(nameof(domainResolver));
        _stateDataFormat = stateDataFormat ?? throw new ArgumentNullException(nameof(stateDataFormat));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        
        _cache = cache ?? new MemoryConfigurationManagerCache();
        _ownsCache = cache == null;
    }

    /// <summary>
    /// Retrieves the OpenID Connect configuration for the current request's resolved domain.
    /// </summary>
    /// <param name="cancel">A cancellation token to observe while waiting for the task to complete.</param>
    /// <returns>The OpenID Connect configuration for the resolved domain.</returns>
    /// <exception cref="InvalidOperationException">Thrown when HttpContext is unavailable, or domain resolution fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the manager has been disposed.</exception>
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        ThrowIfDisposed();
        
        var httpContext = _httpContextAccessor.HttpContext;

        if (httpContext == null)
        {
            throw new InvalidOperationException(
                "HttpContext is not available. Ensure this method is called within an active HTTP request context.");
        }

        var authority = await ResolveAuthorityAsync(httpContext).ConfigureAwait(false);
        var metadataAddress = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";

        var manager = _cache.GetOrCreate(metadataAddress, CreateConfigurationManager);

        return await manager.GetConfigurationAsync(cancel).ConfigureAwait(false);
    }

    /// <summary>
    /// Requests that all cached configurations be refreshed on their next access.
    /// </summary>
    /// <remarks>
    /// Clears the cache, forcing new configuration managers to be created on subsequent requests.
    /// </remarks>
    public void RequestRefresh()
    {
        if (_disposed)
        {
            return;
        }
        
        _cache.Clear();
    }

    /// <summary>
    /// Resolves the Auth0 authority (issuer URL) for the current request.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <returns>The resolved authority URL.</returns>
    /// <exception cref="InvalidOperationException">Thrown when domain resolution fails.</exception>
    internal async Task<string> ResolveAuthorityAsync(HttpContext context)
    {
        // In case of a callback request, extracts the issuer from the state parameter.
        if (TryGetState(context, out var state) && TryGetIssuerFromState(state, out var stateIssuer))
        {
            return Utils.ToAuthority(stateIssuer);
        }

        // Check if the domain was already resolved earlier in the request pipeline
        if (context.Items[Auth0Constants.ResolvedDomainKey] is string cachedDomain &&
            !string.IsNullOrWhiteSpace(cachedDomain))
        {
            return Utils.ToAuthority(cachedDomain);
        }

        // Invoke the domain resolver to determine the domain for this request
        var resolved = await _domainResolver(context).ConfigureAwait(false);
        
        if (string.IsNullOrWhiteSpace(resolved))
        {
            throw new InvalidOperationException(
                "DomainResolver returned a null or empty value. " +
                "Ensure the configured resolver returns a valid Auth0 domain.");
        }

        // Cache the resolved domain for subsequent use in this request
        context.Items[Auth0Constants.ResolvedDomainKey] = resolved;
        return Utils.ToAuthority(resolved);
    }

    /// <summary>
    /// Attempts to extract the state parameter from the incoming request.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="state">The extracted state value, if found.</param>
    /// <returns>True if state was found; otherwise, false.</returns>
    /// <remarks>
    /// Checks both query string (GET requests) and form data (POST requests).
    /// </remarks>
    internal static bool TryGetState(HttpContext context, out string? state)
    {
        // Check query string first (most common for OAuth/OIDC callbacks)
        if (context.Request.Query.TryGetValue("state", out var queryState) && 
            !string.IsNullOrWhiteSpace(queryState))
        {
            state = queryState.ToString();
            return true;
        }

        // Check form data for POST callbacks
        if (context.Request.HasFormContentType && 
            context.Request.Form.TryGetValue("state", out var formState) &&
            !string.IsNullOrWhiteSpace(formState))
        {
            state = formState.ToString();
            return true;
        }

        state = null;
        return false;
    }

    /// <summary>
    /// Attempts to extract the issuer (domain) from a protected state parameter.
    /// </summary>
    /// <param name="state">The protected state string.</param>
    /// <param name="issuer">The extracted issuer, if found.</param>
    /// <returns>True if the issuer was successfully extracted; otherwise, false.</returns>
    /// <remarks>
    /// This method safely handles malformed or tampered state parameters by catching
    /// deserialization exceptions. This is expected behavior for invalid/expired state.
    /// </remarks>
    internal bool TryGetIssuerFromState(string? state, out string issuer)
    {
        issuer = string.Empty;

        if (string.IsNullOrWhiteSpace(state))
        {
            return false;
        }

        AuthenticationProperties? props;
        try
        {
            props = _stateDataFormat.Unprotect(state);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or 
                                         FormatException or 
                                         ArgumentException)
        {
            // State parameter is invalid, malformed, or has been tampered with
            // This is expected in certain scenarios (e.g., expired/corrupted state)
            return false;
        }

        if (props?.Items == null)
        {
            return false;
        }

        if (props.Items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var value) &&
            !string.IsNullOrWhiteSpace(value))
        {
            issuer = value;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Creates a new configuration manager for a specific metadata address.
    /// </summary>
    /// <param name="address">The OpenID Connect metadata endpoint URL.</param>
    /// <returns>A configured instance of <see cref="ConfigurationManager{OpenIdConnectConfiguration}"/>.</returns>
    internal IConfigurationManager<OpenIdConnectConfiguration> CreateConfigurationManager(string address)
    {
        var retriever = new HttpDocumentRetriever(_httpClient)
        {
            RequireHttps = address.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        };

        return new ConfigurationManager<OpenIdConnectConfiguration>(
            address,
            new OpenIdConnectConfigurationRetriever(),
            retriever);
    }
    
    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if this instance has been disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }
    }
    
    /// <summary>
    /// Releases all resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Disposes the cache only if it was created internally (not provided by the user).
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        
        _disposed = true;
        
        if (_ownsCache)
        {
            _cache.Dispose();
        }
    }
}