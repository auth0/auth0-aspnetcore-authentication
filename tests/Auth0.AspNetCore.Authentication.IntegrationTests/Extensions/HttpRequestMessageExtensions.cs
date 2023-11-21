using System.Net.Http;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Extensions
{
    /// <summary>
    /// HttpRequestMessage Extensions to be able to easily filter certain requests.
    /// </summary>
    public static class HttpRequestMessageExtensions
    {
        /// <summary>
        /// Indicate whether or not the HttpRequestMessage points to `.well-known/openid-configuration`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request points to `.well-known/openid-configuration`, false if not.</returns>
        public static bool IsOpenIdConfigurationEndPoint(this HttpRequestMessage me)
        {
            return me.RequestUri.AbsolutePath.Contains(".well-known/openid-configuration");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage points to `.well-known/jwks.json`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request points to `.well-known/jwks.json`, false if not.</returns>
        public static bool IsJwksEndPoint(this HttpRequestMessage me)
        {
            return me.RequestUri.AbsolutePath.Contains(".well-known/jwks.json");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage points to `oauth/token`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request points to `oauth/token`, false if not.</returns>
        public static bool IsTokenEndPoint(this HttpRequestMessage me)
        {
            return me.RequestUri.AbsolutePath.Contains("oauth/token");
        }
        
        /// <summary>
        /// Indicate whether or not the HttpRequestMessage points to `oauth/par`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request points to `oauth/par`, false if not.</returns>
        public static bool IsPAREndPoint(this HttpRequestMessage me)
        {
            return me.RequestUri.AbsolutePath.Contains("oauth/par");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage countains the `Auth0-Client` header.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request countains the `Auth0-Client` header, false if not.</returns>
        public static bool HasAuth0ClientHeader(this HttpRequestMessage me)
        {
            return me.Headers.Contains("Auth0-Client");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage contains the provided `grant_type`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request countains the provided `grant_type`, false if not.</returns>
        public static bool HasGrantType(this HttpRequestMessage me, string grantType)
        {
            return me.HasBody("grant_type", grantType);
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage contains a `client_secret`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request countains a `client_secret`, false if not.</returns>
        public static bool HasClientSecret(this HttpRequestMessage me)
        {
            return me.HasBody($"client_secret");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage contains a `client_assertion` and `client_assertion_type`.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request countains a `client_assertion` and `client_assertion_type`, false if not.</returns>
        public static bool HasClientAssertion(this HttpRequestMessage me)
        {
            return me.HasBody($"client_assertion") && me.HasBody($"client_assertion_type");
        }

        /// <summary>
        /// Indicate whether or not the HttpRequestMessage contains the specified property and value, if provided.
        /// </summary>
        /// <param name="me">The HttpRequestMessage to inspect.</param>
        /// <returns>True if the request countains the property and value, false if not.</returns>
        private static bool HasBody(this HttpRequestMessage me, string key, string value = null)
        {
            var content = me.Content.ReadAsStringAsync().Result;

            if (!string.IsNullOrEmpty(value))
            {
                return content.Contains($"{key}={value}");
            }

            return content.Contains($"{key}=");
        }
    }
}
