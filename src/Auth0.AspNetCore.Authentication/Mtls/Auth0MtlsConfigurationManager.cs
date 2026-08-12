using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Decorates an OpenID Connect <see cref="IConfigurationManager{T}"/> so that, once mTLS is
    /// enabled, Microsoft's <c>OpenIdConnectHandler</c> and the SDK's PAR handler redeem against the
    /// <c>mtls_endpoint_aliases</c> hosts. Neither handler routes through SDK code that can substitute
    /// a URL per request, so the aliases are applied by rewriting the discovered configuration's
    /// <see cref="OpenIdConnectConfiguration.TokenEndpoint"/> and
    /// <see cref="OpenIdConnectConfiguration.PushedAuthorizationRequestEndpoint"/>.
    /// </summary>
    /// <remarks>
    /// Rewriting reads the alias from <c>AdditionalData</c> (which discovery never mutates), so
    /// re-applying it to the same cached configuration object is idempotent.
    /// </remarks>
    internal sealed class Auth0MtlsConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _inner;

        public Auth0MtlsConfigurationManager(IConfigurationManager<OpenIdConnectConfiguration> inner)
        {
            _inner = inner;
        }

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            var configuration = await _inner.GetConfigurationAsync(cancel).ConfigureAwait(false);

            var tokenAlias = MtlsEndpointAliases.TryGetAlias(configuration, "token_endpoint");
            if (!string.IsNullOrEmpty(tokenAlias))
            {
                configuration.TokenEndpoint = tokenAlias;
            }

            var parAlias = MtlsEndpointAliases.TryGetAlias(configuration, "pushed_authorization_request_endpoint");
            if (!string.IsNullOrEmpty(parAlias))
            {
                configuration.PushedAuthorizationRequestEndpoint = parAlias;
            }

            return configuration;
        }

        public void RequestRefresh() => _inner.RequestRefresh();
    }
}
