using System.Net.Http;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public static class HttpRequestMessageExtensions
    {
        public static bool IsTokenEndPoint(this HttpRequestMessage me)
        {
            return me.RequestUri.AbsolutePath.Contains("oauth/token");
        }

        public static bool HasAuth0ClientHeader(this HttpRequestMessage me)
        {
            return me.Headers.Contains("Auth0-Client");
        }
    }
}
