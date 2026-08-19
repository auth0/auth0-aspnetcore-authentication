using System;
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
    internal sealed class Auth0MtlsConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>, IDisposable
    {
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _inner;

        public Auth0MtlsConfigurationManager(IConfigurationManager<OpenIdConnectConfiguration> inner)
        {
            _inner = inner;
        }

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            var configuration = await _inner.GetConfigurationAsync(cancel).ConfigureAwait(false);

            // token_endpoint is required: the code exchange cannot fall back to the standard host under
            // mTLS (the edge only forwards the certificate on the mtls alias), so a missing alias must
            // fail closed with the same actionable error the back-channel resolver raises — not silently
            // leave the standard endpoint in place and defer to a downstream invalid_client.
            configuration.TokenEndpoint = MtlsEndpointAliases.GetRequiredAlias(configuration, "token_endpoint");

            // PAR is optional: this rewrite runs on every configuration fetch whether or not PAR is in
            // use, so a tenant without a PAR alias is not a misconfiguration and must not throw here. The
            // PAR handler's own resolver fails closed if PAR is actually attempted without an alias.
            var parAlias = MtlsEndpointAliases.TryGetAlias(configuration, "pushed_authorization_request_endpoint");
            if (!string.IsNullOrEmpty(parAlias))
            {
                configuration.PushedAuthorizationRequestEndpoint = parAlias;
            }

            return configuration;
        }

        public void RequestRefresh() => _inner.RequestRefresh();

        public void Dispose() => (_inner as IDisposable)?.Dispose();
    }
}
