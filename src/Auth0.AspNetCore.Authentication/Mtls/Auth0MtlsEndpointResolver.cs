using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Resolves the <c>mtls_endpoint_aliases</c> endpoints from an Auth0 tenant's discovery document.
    /// Used by the back-channel paths that build their own request URIs (<see cref="TokenClient"/> and
    /// <see cref="AuthenticationApi.AuthenticationApiClient"/>). Discovery is fetched once per domain
    /// and cached, so <see cref="AuthenticationApi.AuthenticationApiClient"/> can resolve synchronously
    /// after the first call without repeated network round-trips. Registered as a singleton.
    /// </summary>
    internal sealed class Auth0MtlsEndpointResolver
    {
        private readonly ConcurrentDictionary<string, Task<OpenIdConnectConfiguration>> _cache =
            new ConcurrentDictionary<string, Task<OpenIdConnectConfiguration>>();

        /// <summary>Resolves the aliased token endpoint for <paramref name="domain"/>.</summary>
        public Task<string> ResolveTokenEndpointAsync(string domain, HttpClient httpClient, CancellationToken cancellationToken = default)
            => ResolveAsync(domain, "token_endpoint", httpClient, cancellationToken);

        /// <summary>Resolves the aliased pushed authorization request (PAR) endpoint for <paramref name="domain"/>.</summary>
        public Task<string> ResolvePushedAuthorizationRequestEndpointAsync(string domain, HttpClient httpClient, CancellationToken cancellationToken = default)
            => ResolveAsync(domain, "pushed_authorization_request_endpoint", httpClient, cancellationToken);

        private async Task<string> ResolveAsync(string domain, string endpointName, HttpClient httpClient, CancellationToken cancellationToken)
        {
            var task = _cache.GetOrAdd(domain, d => OpenIdConnectConfigurationRetriever.GetAsync(
                $"https://{d}/.well-known/openid-configuration", httpClient, cancellationToken));

            OpenIdConnectConfiguration configuration;
            try
            {
                configuration = await task.ConfigureAwait(false);
            }
            catch
            {
                // Do not cache a failed discovery attempt: a transient failure must not poison the
                // domain.
                _cache.TryRemove(new KeyValuePair<string, Task<OpenIdConnectConfiguration>>(domain, task));
                throw;
            }

            return MtlsEndpointAliases.GetRequiredAlias(configuration, endpointName);
        }
    }
}
