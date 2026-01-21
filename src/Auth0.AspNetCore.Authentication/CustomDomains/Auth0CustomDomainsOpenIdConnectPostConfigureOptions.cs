using System;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.CustomDomains
{
    /// <summary>
    /// Post-configures <see cref="OpenIdConnectOptions"/> to support Auth0 multiple custom domains.
    /// </summary>
    /// <remarks>
    /// This configurator sets up a custom <see cref="Auth0CustomDomainsOpenIdConnectConfigurationManager"/>
    /// that maintains separate OpenID Connect configurations per domain, enabling dynamic issuer resolution
    /// based on the current request context.
    /// </remarks>
    internal sealed class Auth0CustomDomainsOpenIdConnectPostConfigureOptions : IPostConfigureOptions<OpenIdConnectOptions>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IOptionsMonitor<Auth0CustomDomainsOptions> _auth0CustomDomainsOptionsMonitor;
        private readonly IHttpClientFactory? _httpClientFactory;

        /// <summary>
        /// Initializes a new instance of the <see cref="Auth0CustomDomainsOpenIdConnectPostConfigureOptions"/> class.
        /// </summary>
        /// <param name="httpContextAccessor">The HTTP context accessor for retrieving the current request context.</param>
        /// <param name="auth0CustomDomainsOptionsMonitor">The options monitor for Auth0 custom domains configuration.</param>
        /// <param name="httpClientFactory">Optional HTTP client factory for creating HTTP clients.
        /// If not provided, the OpenIdConnect backchannel will be used.</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public Auth0CustomDomainsOpenIdConnectPostConfigureOptions(
            IHttpContextAccessor httpContextAccessor,
            IOptionsMonitor<Auth0CustomDomainsOptions> auth0CustomDomainsOptionsMonitor,
            IHttpClientFactory? httpClientFactory = null)
        {
            ArgumentNullException.ThrowIfNull(httpContextAccessor);
            ArgumentNullException.ThrowIfNull(auth0CustomDomainsOptionsMonitor);

            _httpContextAccessor = httpContextAccessor;
            _auth0CustomDomainsOptionsMonitor = auth0CustomDomainsOptionsMonitor;
            _httpClientFactory = httpClientFactory;
        }

        /// <summary>
        /// Post-configures the specified <see cref="OpenIdConnectOptions"/> with Auth0 custom domains support.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        /// <exception cref="InvalidOperationException">Thrown when <c>StateDataFormat</c> is not configured.</exception>
        public void PostConfigure(string? name, OpenIdConnectOptions options)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            var auth0CustomDomainsOptions = _auth0CustomDomainsOptionsMonitor.Get(name);

            if (!auth0CustomDomainsOptions.IsMultipleCustomDomainsEnabled)
            {
                return;
            }
            
            // Ensure DomainResolver is configured
            if (auth0CustomDomainsOptions.DomainResolver is null)
            {
                throw new InvalidOperationException(
                    $"DomainResolver must be configured when custom domains are enabled. " +
                    $"Set the {nameof(Auth0CustomDomainsOptions.DomainResolver)} property in the {nameof(Auth0CustomDomainsOptions)} configuration.");
            }
            
            // Ensure we have a StateDataFormat for extracting the issuer on callback requests.
            if (options.StateDataFormat is null)
            {
                throw new InvalidOperationException(
                    $"OpenIdConnectOptions.StateDataFormat is not configured. " +
                    $"This is required for Auth0 custom domains support. " +
                    $"Ensure the OpenIdConnect authentication scheme is properly configured.");
            }
            
            if (options.Backchannel is null && _httpClientFactory is null)
            {
                throw new InvalidOperationException(
                    $"Either OpenIdConnectOptions.Backchannel or IHttpClientFactory must be configured. " +
                    $"Configure a Backchannel HttpClient on OpenIdConnectOptions or register IHttpClientFactory in the service collection.");
            }
            
            var httpClient = options.Backchannel ?? _httpClientFactory!.CreateClient();

            options.ConfigurationManager = new Auth0CustomDomainsOpenIdConnectConfigurationManager(
                _httpContextAccessor,
                auth0CustomDomainsOptions.DomainResolver,
                options.StateDataFormat,
                httpClient,
                auth0CustomDomainsOptions.ConfigurationManagerCache);

            // The issuer varies per request, so we can't validate against a single static issuer string.
            // Issuer validation will instead be performed via the OnTokenValidated event.
            options.TokenValidationParameters.ValidateIssuer = false;
            
            // Since Domain Resolver is set, this value will be set dynamically, so we clear it here.
            options.Authority = null;
            
        }
    }
}
