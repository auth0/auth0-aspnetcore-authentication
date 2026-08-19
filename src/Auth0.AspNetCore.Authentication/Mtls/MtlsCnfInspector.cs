using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Emits a one-time warning per client when mTLS is enabled but an access token issued on a
    /// <c>cnf</c>-bearing grant (authorization_code, refresh_token) is not certificate-bound.
    /// Registered as a singleton so the gate survives refresh loops for the lifetime of the app.
    /// </summary>
    internal sealed class MtlsCnfInspector
    {
        internal const string Warning =
            "mTLS is enabled but the access token has no `cnf.x5t#S256` claim; the token is not sender-constrained. " +
            "Configure Token Sender-Constraining on the API.";

        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<string, byte> _warned = new ConcurrentDictionary<string, byte>();

        public MtlsCnfInspector(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger("Auth0");
        }

        /// <summary>
        /// Warns (once per <paramref name="clientId"/>) when <paramref name="accessToken"/> is a JWT
        /// with no <c>cnf.x5t#S256</c>. Silent when the claim is present or the token is not an
        /// inspectable JWT.
        /// </summary>
        public void Inspect(string clientId, string? accessToken)
        {
            // Only a JWT that is provably missing the claim warrants a warning; present (true) is fine,
            // and opaque/unparseable (null) is a different problem the SDK cannot diagnose here.
            if (CnfClaimReader.HasThumbprintConfirmation(accessToken) != false)
            {
                return;
            }

            if (_warned.TryAdd(clientId, 0))
            {
                _logger.LogWarning(Warning);
            }
        }
    }
}
