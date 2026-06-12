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
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        public TokenClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<TokenRefreshResult> Refresh(Auth0WebAppOptions options, string refreshToken, string? domain = null, string? audience = null, string? scope = null)
        {
            var body = new Dictionary<string, string> {
                { "grant_type", "refresh_token" },
                { "client_id", options.ClientId },
                { "refresh_token", refreshToken }
            };

            if (!string.IsNullOrWhiteSpace(audience))
            {
                body.Add("audience", audience);
            }

            if (!string.IsNullOrWhiteSpace(scope))
            {
                body.Add("scope", scope);
            }

            // Use provided domain for dynamic resolution, fallback to options.Domain
            var tokenEndpointDomain = domain ?? options.Domain;

            if (string.IsNullOrWhiteSpace(tokenEndpointDomain))
            {
                throw new InvalidOperationException(
                    "Cannot determine domain for token endpoint. " +
                    "Ensure Domain is set or domain resolution is properly configured.");
            }

            ApplyClientAuthentication(options, body, tokenEndpointDomain);

            var requestContent = new FormUrlEncodedContent(body.Select(p => new KeyValuePair<string?, string?>(p.Key, p.Value ?? "")));

            using (var request = new HttpRequestMessage(HttpMethod.Post, $"https://{tokenEndpointDomain}/oauth/token") { Content = requestContent })
            {
                using (var response = await _httpClient.SendAsync(request).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        return await BuildFailure(response).ConfigureAwait(false);
                    }

                    var contentStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);

                    AccessTokenResponse? accessTokenResponse;
                    try
                    {
                        accessTokenResponse = await JsonSerializer.DeserializeAsync<AccessTokenResponse>(contentStream, _jsonSerializerOptions).ConfigureAwait(false);
                    }
                    catch (JsonException)
                    {
                        // The body is over token-bearing bytes (id_token is a JWT of user claims).
                        // Swallow the parse error so it never surfaces as an exposed Exception on the
                        // failure event; report a status-code-only failure with a static, payload-free
                        // message instead.
                        return new TokenRefreshResult
                        {
                            StatusCode = (int)response.StatusCode,
                            Error = "invalid_token_response",
                            ErrorDescription = "The token endpoint returned a response that could not be parsed."
                        };
                    }

                    return accessTokenResponse != null
                        ? TokenRefreshResult.Success(accessTokenResponse)
                        : new TokenRefreshResult { StatusCode = (int)response.StatusCode };
                }
            }
        }

        private static async Task<TokenRefreshResult> BuildFailure(HttpResponseMessage response)
        {
            var result = new TokenRefreshResult { StatusCode = (int)response.StatusCode };

            try
            {
                var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(body))
                {
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        // An "mfa_required" error also carries "mfa_token" and "mfa_requirements";
                        // surfacing those (and completing the MFA flow) is deferred to a subsequent PR.
                        if (root.TryGetProperty("error", out var errorElement))
                        {
                            result.Error = errorElement.GetString();
                        }

                        if (root.TryGetProperty("error_description", out var descriptionElement))
                        {
                            result.ErrorDescription = descriptionElement.GetString();
                        }
                    }
                }
            }
            catch (Exception)
            {
                // A non-JSON or unreadable error body still yields a result carrying the status code.
            }

            return result;
        }

        private void ApplyClientAuthentication(Auth0WebAppOptions options, Dictionary<string, string> body, string domain)
        {
            if (options.ClientAssertionSecurityKey != null)
            {
                body.Add("client_assertion", new JwtTokenFactory(options.ClientAssertionSecurityKey, options.ClientAssertionSecurityKeyAlgorithm ?? SecurityAlgorithms.RsaSha256)
                   .GenerateToken(options.ClientId, $"https://{domain}/", options.ClientId
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
