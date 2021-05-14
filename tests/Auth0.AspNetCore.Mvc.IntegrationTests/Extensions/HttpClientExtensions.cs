using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    /// <summary>
    /// HttpClient Extensions to support a URL as a string as well as cookie headers.
    /// </summary>
    internal static class HttpClientExtensions
    {
        public static Task<HttpResponseMessage> SendAsync(this HttpClient client, string url)
        {
            return client.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
        }

        public static Task<HttpResponseMessage> SendAsync(this HttpClient client, string url, IEnumerable<string> cookieHeaders)
        {
            return SendAsync(client, new HttpRequestMessage(HttpMethod.Get, url), cookieHeaders);
        }

        public static Task<HttpResponseMessage> SendAsync(this HttpClient client, HttpRequestMessage request, IEnumerable<string> cookieHeaders)
        {
            if (cookieHeaders != null)
            {
                foreach (var cookieHeader in cookieHeaders)
                {
                    request.Headers.Add("Cookie", cookieHeader);
                }
            }

            return client.SendAsync(request);
        }
    }

}

