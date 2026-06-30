using Auth0.AspNetCore.Authentication;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
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

            return await Send(body, tokenEndpointDomain).ConfigureAwait(false);
        }

        public async Task<TokenRefreshResult> ExchangeRefreshTokenForConnectionToken(
            Auth0WebAppOptions options,
            string refreshToken,
            string connection,
            string? domain = null,
            string? loginHint = null)
        {
            var body = new Dictionary<string, string>
            {
                { "grant_type", "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token" },
                { "subject_token_type", "urn:ietf:params:oauth:token-type:refresh_token" },
                { "subject_token", refreshToken },
                { "requested_token_type", "http://auth0.com/oauth/token-type/federated-connection-access-token" },
                { "connection", connection },
                { "client_id", options.ClientId }
            };

            if (!string.IsNullOrWhiteSpace(loginHint))
            {
                body.Add("login_hint", loginHint);
            }

            var tokenEndpointDomain = domain ?? options.Domain;

            if (string.IsNullOrWhiteSpace(tokenEndpointDomain))
            {
                throw new InvalidOperationException(
                    "Cannot determine domain for token endpoint. " +
                    "Ensure Domain is set or domain resolution is properly configured.");
            }

            ApplyClientAuthentication(options, body, tokenEndpointDomain);

            return await Send(body, tokenEndpointDomain).ConfigureAwait(false);
        }

        public async Task<TokenRefreshResult> ExchangeCustomToken(
            Auth0WebAppOptions options,
            string subjectToken,
            string subjectTokenType,
            string? audience = null,
            string? scope = null,
            string? actorToken = null,
            string? actorTokenType = null,
            string? organization = null,
            string? domain = null)
        {
            var body = new Dictionary<string, string>
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange" },
                { "client_id", options.ClientId },
                { "subject_token", subjectToken },
                { "subject_token_type", subjectTokenType }
            };

            if (!string.IsNullOrWhiteSpace(audience))
            {
                body.Add("audience", audience);
            }

            if (!string.IsNullOrWhiteSpace(scope))
            {
                body.Add("scope", scope);
            }

            if (!string.IsNullOrWhiteSpace(organization))
            {
                body.Add("organization", organization);
            }

            // The actor pair is added together; the mutual requirement is enforced by validation.
            if (!string.IsNullOrWhiteSpace(actorToken))
            {
                body.Add("actor_token", actorToken);
                body.Add("actor_token_type", actorTokenType!);
            }

            var tokenEndpointDomain = domain ?? options.Domain;

            if (string.IsNullOrWhiteSpace(tokenEndpointDomain))
            {
                throw new InvalidOperationException(
                    "Cannot determine domain for token endpoint. " +
                    "Ensure Domain is set or domain resolution is properly configured.");
            }

            ApplyClientAuthentication(options, body, tokenEndpointDomain);

            return await Send(body, tokenEndpointDomain).ConfigureAwait(false);
        }

        private async Task<TokenRefreshResult> Send(Dictionary<string, string> body, string tokenEndpointDomain)
        {
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
                        return TokenRefreshResult.Failure(
                            (int)response.StatusCode,
                            "invalid_token_response",
                            "The token endpoint returned a response that could not be parsed.");
                    }

                    // A 200 with no usable access_token (e.g. an empty object or a body missing
                    // the field) deserializes to a non-null response whose AccessToken is null.
                    // Treat that as a failure so IsSuccess only ever means "we have a usable token"
                    // and a useless token is never persisted downstream.
                    return !string.IsNullOrEmpty(accessTokenResponse?.AccessToken)
                        ? TokenRefreshResult.Success(accessTokenResponse!)
                        : TokenRefreshResult.Failure(
                            (int)response.StatusCode,
                            "invalid_token_response",
                            "The token endpoint returned a response without an access token.");
                }
            }
        }

        private static async Task<TokenRefreshResult> BuildFailure(HttpResponseMessage response)
        {
            string? error = null;
            string? errorDescription = null;
            string? mfaToken = null;
            MfaRequirements? mfaRequirements = null;

            try
            {
                var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(body))
                {
                    using var document = JsonDocument.Parse(body);
                    var root = document.RootElement;
                    if (root.ValueKind == JsonValueKind.Object)
                    {
                        if (root.TryGetProperty("error", out var errorElement))
                        {
                            error = errorElement.GetString();
                        }

                        if (root.TryGetProperty("error_description", out var descriptionElement))
                        {
                            errorDescription = descriptionElement.GetString();
                        }

                        if (root.TryGetProperty("mfa_token", out var mfaTokenElement))
                        {
                            mfaToken = mfaTokenElement.GetString();
                        }

                        if (root.TryGetProperty("mfa_requirements", out var mfaRequirementsElement) &&
                            mfaRequirementsElement.ValueKind == JsonValueKind.Object)
                        {
                            try
                            {
                                mfaRequirements = mfaRequirementsElement.Deserialize<MfaRequirements>();
                            }
                            catch (JsonException)
                            {
                                // Best-effort: a shape we can't map is simply omitted.
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                // A non-JSON or unreadable error body still yields a result carrying the status code.
            }

            return TokenRefreshResult.Failure((int)response.StatusCode, error, errorDescription, mfaToken, mfaRequirements);
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
