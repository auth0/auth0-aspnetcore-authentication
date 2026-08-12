using System.Net.Http;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Options for configuring Mutual TLS (mTLS) client authentication via
    /// <see cref="Auth0WebAppAuthenticationBuilder.WithMtls"/>.
    /// </summary>
    public class Auth0MtlsOptions
    {
        /// <summary>
        /// The <see cref="System.Net.Http.HttpClient"/> configured with the client certificate. It is
        /// used for every client-authenticated back-channel request (token endpoint, MFA challenge,
        /// PAR, and the code exchange performed by the OpenID Connect handler). The SDK never reads or
        /// stores the certificate itself — attach it to this client's transport
        /// (for example a <c>SocketsHttpHandler</c> with <c>SslClientAuthenticationOptions</c>).
        /// The client should be long-lived so the TLS connection pool is reused across requests.
        /// </summary>
        public HttpClient? HttpClient { get; set; }
    }
}
