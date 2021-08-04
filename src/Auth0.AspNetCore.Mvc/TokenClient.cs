using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    internal class TokenClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly bool _isHttpClientOwner;
        private readonly JsonSerializerOptions _jsonSerializerOptions = new JsonSerializerOptions()
        {
            IgnoreNullValues = true,
        };

        public TokenClient(HttpClient httpClient = null)
        {
            _isHttpClientOwner = httpClient == null;
            _httpClient = httpClient ?? new HttpClient();
        }

        public void Dispose()
        {
            if (_isHttpClientOwner)
            {
                _httpClient.Dispose();
            }
        }

        public async Task<AccessTokenResponse> Refresh(Auth0WebAppOptions options, string refreshToken)
        {
            var body = new Dictionary<string, string> {
                { "grant_type", "refresh_token" },
                { "client_id", options.ClientId },
                { "client_secret", options.ClientSecret },
                { "refresh_token", refreshToken }
            };

            var requestContent = new FormUrlEncodedContent(body.Select(p => new KeyValuePair<string, string>(p.Key, p.Value ?? "")));

            using (var request = new HttpRequestMessage(HttpMethod.Post, $"https://{options.Domain}/oauth/token") { Content = requestContent })
            {
                using (var response = await _httpClient.SendAsync(request).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    var contentStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

                    return await JsonSerializer.DeserializeAsync<AccessTokenResponse>(contentStream, _jsonSerializerOptions).ConfigureAwait(false);
                }
            }
        }
    }
}
