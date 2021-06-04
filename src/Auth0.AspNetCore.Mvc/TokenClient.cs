using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    public class TokenClient : IDisposable
    {
        private readonly HttpClient httpClient;
        private readonly bool isHttpClientOwner;
        private readonly JsonSerializerSettings jsonSerializerSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DateParseHandling = DateParseHandling.DateTime
        };


        public TokenClient(HttpClient httpClient)
        {
            this.isHttpClientOwner = httpClient == null;
            this.httpClient = httpClient ?? new HttpClient();
        }

        public void Dispose()
        {
            if (this.isHttpClientOwner)
            {
                this.httpClient.Dispose();
            }
        }

        public async Task<AccessTokenResponse> Refresh(Auth0Options options, string refreshToken)
        {
            var body = new Dictionary<string, string> {
                            { "grant_type", "refresh_token" },
                            { "client_id", options.ClientId },
                            { "client_secret", options.ClientSecret },
                            { "refresh_token", refreshToken }
                        };

            using (var request = new HttpRequestMessage(HttpMethod.Post, $"https://{options.Domain}/oauth/token") { Content = new FormUrlEncodedContent(body.Select(p => new KeyValuePair<string, string>(p.Key, p.Value ?? ""))) })
            {
                using (var response = await httpClient.SendAsync(request).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                    return typeof(AccessTokenResponse) == typeof(string)
                        ? (AccessTokenResponse)(object)content
                        : JsonConvert.DeserializeObject<AccessTokenResponse>(content, jsonSerializerSettings);
                }
            }
        }
    }
}
