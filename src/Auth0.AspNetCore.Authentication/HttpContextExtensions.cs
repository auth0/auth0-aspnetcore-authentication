using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// <see cref="HttpContext"/> extensions for retrieving access tokens, including
    /// on-demand tokens for additional audiences/scopes (Multi-Resource Refresh Token).
    /// </summary>
    public static class HttpContextExtensions
    {
        internal const string AccessTokensItemKey = ".Token.access_tokens";

        /// <summary>
        /// Retrieves an access token for the audience/scope described by <paramref name="request"/>.
        /// Reuses a cached token from the session when one is present and not expired; otherwise
        /// exchanges the session's refresh token for a new token and persists it.
        /// </summary>
        /// <remarks>
        /// This method is not safe to call concurrently for the same session. It reads the session,
        /// modifies the stored tokens in memory, and writes them back; concurrent calls each operate on
        /// their own snapshot, so the last write wins and a freshly fetched token from another in-flight
        /// call can be silently dropped. More importantly, when refresh-token rotation is enabled,
        /// concurrent calls exchange the same refresh token: the second exchange presents an
        /// already-rotated token, which can trigger refresh-token reuse detection and invalidate the
        /// entire session.
        /// <para>
        /// To avoid this, ensure only one <see cref="GetAccessTokenAsync"/> call is in flight per session
        /// at a time. Either don't issue parallel requests that each trigger a refresh, or plug in a
        /// server-side session store via
        /// <see cref="Auth0WebAppAuthenticationBuilder.WithSessionStore(Microsoft.AspNetCore.Authentication.Cookies.ITicketStore)"/>
        /// whose <c>ITicketStore</c> serializes concurrent access per session.
        /// </para>
        /// </remarks>
        /// <param name="context">The current <see cref="HttpContext"/>.</param>
        /// <param name="request">The audience/scope to request a token for.</param>
        /// <param name="scheme">The Auth0 authentication scheme. Defaults to <see cref="Auth0Constants.AuthenticationScheme"/>.</param>
        /// <returns>The access token, or <c>null</c> when no refresh token is available or the refresh failed.</returns>
        /// <exception cref="MfaRequiredException">
        /// Thrown when the token exchange returns an <c>mfa_required</c> error carrying an <c>mfa_token</c>.
        /// This is a recoverable challenge rather than a terminal failure: drive the MFA challenge/verify
        /// flow with <see cref="AuthenticationApi.IAuthenticationApiClient"/> (registered via
        /// <see cref="Auth0WebAppAuthenticationBuilder.WithAuthenticationApiClient"/>) using the
        /// <see cref="MfaRequiredException.MfaToken"/> blob. A malformed <c>mfa_required</c> response with no
        /// <c>mfa_token</c> is folded into the refresh-failed path instead.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// Thrown when a refresh succeeds but the new token cannot be persisted because the response has
        /// already started. Persisting the refreshed token calls <see cref="AuthenticationHttpContextExtensions.SignInAsync(HttpContext, string?, System.Security.Claims.ClaimsPrincipal, AuthenticationProperties?)"/>,
        /// which writes the authentication cookie; if the headers have already been sent, this throws and
        /// the exception propagates out of this method rather than being folded into the refresh-failed path.
        /// </exception>
        public static async Task<string?> GetAccessTokenAsync(this HttpContext context, AccessTokenRequest request, string? scheme = null)
        {
            scheme ??= Auth0Constants.AuthenticationScheme;

            var options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(scheme);
            var optionsWithAccessToken = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(scheme);

            var audience = request.Audience ?? optionsWithAccessToken.Audience;
            var mergedScope = TokenSetHelpers.MergeScopeWithDefaults(request.Scope, audience, optionsWithAccessToken.Scope, optionsWithAccessToken.ScopeByAudience);

            var authenticateResult = await context.AuthenticateAsync(options.CookieAuthenticationScheme).ConfigureAwait(false);
            if (!authenticateResult.Succeeded || authenticateResult.Properties == null)
            {
                return null;
            }

            var properties = authenticateResult.Properties;
            var matchesPrimaryToken = MatchesPrimaryToken(audience, mergedScope, optionsWithAccessToken);

            // 1. Try to satisfy the request from what is already stored in the session,
            //    unless the caller explicitly asked to bypass the cache.
            if (!request.ForceRefresh)
            {
                if (matchesPrimaryToken)
                {
                    if (properties.Items.TryGetValue(".Token.access_token", out var primaryToken) &&
                        !string.IsNullOrEmpty(primaryToken) &&
                        !IsPrimaryExpired(properties, optionsWithAccessToken.AccessTokenExpirationLeeway))
                    {
                        return primaryToken;
                    }
                }
                else
                {
                    var sets = ReadAccessTokenSets(properties);
                    var match = TokenSetHelpers.FindAccessTokenSet(sets, audience!, mergedScope, ScopeMatchMode.RequestedScope);
                    if (match != null && match.ExpiresAt > DateTimeOffset.UtcNow.Add(optionsWithAccessToken.AccessTokenExpirationLeeway).ToUnixTimeSeconds())
                    {
                        return match.AccessToken;
                    }
                }
            }

            // 2. No usable token cached — we need the refresh token to obtain one.
            if (!properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
            {
                if (optionsWithAccessToken.Events?.OnMissingRefreshToken != null)
                {
                    await optionsWithAccessToken.Events.OnMissingRefreshToken(context).ConfigureAwait(false);
                }

                return null;
            }

            var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
            var tokenClient = new TokenClient(httpClient);
            var resolvedDomain = context.GetResolvedDomain();

            TokenRefreshResult result;
            try
            {
                result = await tokenClient.Refresh(options, refreshToken, resolvedDomain, audience, mergedScope).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Any refresh failure — transport error, malformed response, or misconfiguration —
                // is folded into the same failure path as a token-endpoint rejection, so callers
                // have a single failure protocol and nothing escapes this method.
                await FireRefreshFailed(optionsWithAccessToken,
                    AccessTokenRefreshFailedContext.FromException(context, audience, mergedScope, ex)).ConfigureAwait(false);
                return null;
            }

            if (!result.IsSuccess)
            {
                // mfa_required is a recoverable challenge, not a terminal/transient refresh failure:
                // surface it as a typed exception so the caller can drive
                // the MFA flow. 
                // A mfa_required response with no mfa_token is malformed and cannot drive the flow, so it falls
                // through to the refresh-failed path rather than yielding a blob that can never
                // be unprotected.
                if (result.Error == "mfa_required" && !string.IsNullOrEmpty(result.MfaToken))
                {
                    var protector = context.RequestServices.GetRequiredService<IMfaTokenProtector>();
                    var mfaContext = new MfaTokenContext
                    {
                        MfaToken = result.MfaToken!,
                        Audience = audience,
                        Scope = mergedScope,
                        MfaRequirements = result.MfaRequirements
                    };
                    var blob = protector.Protect(mfaContext);

                    throw new MfaRequiredException(
                        blob,
                        result.MfaRequirements,
                        (HttpStatusCode)(result.StatusCode ?? (int)HttpStatusCode.Forbidden),
                        new Exceptions.ApiError { Error = result.Error, Message = result.ErrorDescription ?? string.Empty });
                }

                await FireRefreshFailed(optionsWithAccessToken,
                    AccessTokenRefreshFailedContext.FromHttpRejection(context, audience, mergedScope, result.StatusCode, result.Error, result.ErrorDescription)).ConfigureAwait(false);
                return null;
            }

            var response = result.Response!;

            // 3. Merge the new token into the session (primary slot or additional array) and persist.
            ApplyTokenResponse(properties, response, audience, mergedScope, matchesPrimaryToken);

            await context.SignInAsync(options.CookieAuthenticationScheme, authenticateResult.Principal!, properties).ConfigureAwait(false);

            return response.AccessToken;
        }

        /// <summary>
        /// Retrieves the resolved domain from the <see cref="HttpContext.Items"/> collection.
        /// </summary>
        /// <param name="httpContext">The current HTTP context.</param>
        /// <returns>
        /// The resolved domain as a <c>string</c> if present; otherwise, <c>null</c>.
        /// </returns>
        internal static string? GetResolvedDomain(this HttpContext httpContext)
        {
            return httpContext.Items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var domainObj)
                ? domainObj as string
                : null;
        }

        /// <summary>
        /// Fires the <see cref="Auth0WebAppWithAccessTokenEvents.OnAccessTokenRefreshFailed"/> event
        /// with the details of a failed refresh, when a subscriber is configured.
        /// </summary>
        private static async Task FireRefreshFailed(Auth0WebAppWithAccessTokenOptions optionsWithAccessToken, AccessTokenRefreshFailedContext failedContext)
        {
            if (optionsWithAccessToken.Events?.OnAccessTokenRefreshFailed != null)
            {
                await optionsWithAccessToken.Events.OnAccessTokenRefreshFailed(failedContext).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Determines whether the requested audience/scope matches the application's primary
        /// (login-time) token — the one stored in the <c>.Token.access_token</c> slot — rather
        /// than an additional MRRT audience/scope kept in the access-token sets.
        /// </summary>
        private static bool MatchesPrimaryToken(string? audience, string? mergedScope, Auth0WebAppWithAccessTokenOptions options)
        {
            var matchesPrimaryAudience = audience == null || audience == options.Audience;

            var primaryScope = TokenSetHelpers.GetScopeForAudience(options.Scope, options.ScopeByAudience, audience);
            var matchesPrimaryScope = string.IsNullOrEmpty(mergedScope) || TokenSetHelpers.CompareScopes(primaryScope, mergedScope);

            return matchesPrimaryAudience && matchesPrimaryScope;
        }

        private static bool IsPrimaryExpired(AuthenticationProperties properties, TimeSpan leeway)
        {
            if (!properties.Items.TryGetValue(".Token.expires_at", out var expiresAtRaw) || string.IsNullOrEmpty(expiresAtRaw))
            {
                return true;
            }

            // Treat an unparseable timestamp as expired so the token is re-fetched rather
            // than throwing out of a cache check on a malformed session value.
            if (!DateTimeOffset.TryParse(expiresAtRaw, out var expiresAt))
            {
                return true;
            }

            return DateTimeOffset.Compare(expiresAt, DateTimeOffset.Now.Add(leeway)) <= 0;
        }

        private static void ApplyTokenResponse(AuthenticationProperties properties, AccessTokenResponse response, string? audience, string? mergedScope, bool matchesPrimaryToken)
        {
            if (matchesPrimaryToken)
            {
                properties.UpdateTokenValue("access_token", response.AccessToken);
                properties.UpdateTokenValue("expires_at", DateTimeOffset.Now.AddSeconds(response.ExpiresIn).ToString("o"));
            }
            else
            {
                var sets = ReadAccessTokenSets(properties);
                var updated = TokenSetHelpers.UpsertAccessTokenSet(sets, audience!, mergedScope, response);
                WriteAccessTokenSets(properties, updated);
            }

            // Rotation + id_token refresh apply regardless of which slot was updated.
            if (!string.IsNullOrEmpty(response.RefreshToken))
            {
                properties.UpdateTokenValue("refresh_token", response.RefreshToken);
            }

            if (!string.IsNullOrEmpty(response.IdToken))
            {
                properties.UpdateTokenValue("id_token", response.IdToken);
            }
        }

        private static List<AccessTokenSet> ReadAccessTokenSets(AuthenticationProperties properties)
        {
            if (properties.Items.TryGetValue(AccessTokensItemKey, out var json) && !string.IsNullOrEmpty(json))
            {
                // Corrupted or version-skewed session data is treated as a cache miss: the
                // token gets re-fetched, which is preferable to throwing out of a public method.
                try
                {
                    return JsonSerializer.Deserialize<List<AccessTokenSet>>(json) ?? new List<AccessTokenSet>();
                }
                catch (JsonException)
                {
                    return new List<AccessTokenSet>();
                }
            }

            return new List<AccessTokenSet>();
        }

        private static void WriteAccessTokenSets(AuthenticationProperties properties, List<AccessTokenSet> sets)
        {
            properties.Items[AccessTokensItemKey] = JsonSerializer.Serialize(sets);
        }
    }
}
