using Auth0.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    internal class TokenClient
    {
        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonSerializerOptions = new JsonSerializerOptions()
        {
            IgnoreNullValues = true,
        };

        public TokenClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<AccessTokenResponse?> Refresh(Auth0WebAppOptions options, string refreshToken)
        {
            var body = new Dictionary<string, string> {
                { "grant_type", "refresh_token" },
                { "client_id", options.ClientId },
                { "refresh_token", refreshToken },                
            };

            if (options.ForceScopeInRefreshRequests == true) {
                body.Add("scope", options.Scope);
            }

            ApplyClientAuthentication(options, body);

            var requestContent = new FormUrlEncodedContent(body.Select(p => new KeyValuePair<string?, string?>(p.Key, p.Value ?? "")));

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

        private void ApplyClientAuthentication(Auth0WebAppOptions options, Dictionary<string, string> body)
        {
            if (options.ClientAssertionSecurityKey != null)
            {
                body.Add("client_assertion", new JwtTokenFactory(options.ClientAssertionSecurityKey, options.ClientAssertionSecurityKeyAlgorithm ?? SecurityAlgorithms.RsaSha256)
                   .GenerateToken(options.ClientId, $"https://{options.Domain}/", options.ClientId
                ));

                body.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            }
            else
            {
                body.Add("client_secret", options.ClientSecret!);
            }
        }
    }
}
