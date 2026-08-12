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
        internal const string ConnectionTokensItemKey = ".Token.connection_tokens";

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

            // Hard pre-check against the upstream-IdP session ceiling (session_expiry): once reached,
            // never serve a cached token or call the token endpoint — surface no-session (null) so the
            // caller's re-auth path runs. Absent ceiling falls through to existing behavior.
            if (SessionExpiryHelpers.IsSessionExpired(properties, DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
            {
                return null;
            }

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

            // 2. No usable token cached - we need the refresh token to obtain one.
            if (!properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
            {
                if (optionsWithAccessToken.Events?.OnMissingRefreshToken != null)
                {
                    await optionsWithAccessToken.Events.OnMissingRefreshToken(context).ConfigureAwait(false);
                }

                return null;
            }

            var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
            var tokenClient = new TokenClient(
                httpClient,
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.Auth0MtlsEndpointResolver>(),
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector>());
            var resolvedDomain = context.GetResolvedDomain();

            TokenRefreshResult result;
            try
            {
                result = await tokenClient.Refresh(options, refreshToken, resolvedDomain, audience, mergedScope).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Any refresh failure - transport error, malformed response, or misconfiguration -
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
        /// Retrieves a federated connection (Token Vault) access token for the audience/connection
        /// described by <paramref name="request"/> - a third-party API token (e.g. Google, GitHub)
        /// for the logged-in user. Reuses a cached token from the session when one is present and not
        /// expired; otherwise exchanges the session's refresh token for a new connection token and
        /// persists it.
        /// </summary>
        /// <remarks>
        /// Like <see cref="GetAccessTokenAsync"/>, this method is not safe to call concurrently for the
        /// same session: it reads, mutates, and writes the stored tokens, and a concurrent refresh-token
        /// exchange can trip rotation reuse detection. Serialize calls per session.
        /// </remarks>
        /// <param name="context">The current <see cref="HttpContext"/>.</param>
        /// <param name="request">The connection (and optional login hint) to request a token for.</param>
        /// <param name="scheme">The Auth0 authentication scheme. Defaults to <see cref="Auth0Constants.AuthenticationScheme"/>.</param>
        /// <returns>The connection access token, or <c>null</c> when no refresh token is available or the exchange failed.</returns>
        public static async Task<string?> GetAccessTokenForConnectionAsync(this HttpContext context, AccessTokenForConnectionRequest request, string? scheme = null)
        {
            scheme ??= Auth0Constants.AuthenticationScheme;

            var options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(scheme);
            var optionsWithAccessToken = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(scheme);

            var authenticateResult = await context.AuthenticateAsync(options.CookieAuthenticationScheme).ConfigureAwait(false);
            if (!authenticateResult.Succeeded || authenticateResult.Properties == null)
            {
                return null;
            }

            var properties = authenticateResult.Properties;

            // Unlike GetAccessTokenAsync, connection (Token Vault) tokens are intentionally NOT gated
            // by the session_expiry ceiling: they follow the upstream IdP's own token lifetime, so a
            // passed RP session ceiling must not block or tear down this exchange. This matches the
            // auth0-server-python reference (test_get_access_token_for_connection_not_gated_by_ceiling).

            // Normalize the login hint so the cache key matches what is actually sent to the token
            // endpoint, which omits an empty/whitespace hint (see TokenClient). Without this, a "" hint
            // and a null hint would address the same server-side identity but cache under different keys.
            var loginHint = string.IsNullOrWhiteSpace(request.LoginHint) ? null : request.LoginHint;

            // 1. Serve from the per-connection cache unless the caller bypasses it.
            if (!request.ForceRefresh)
            {
                var sets = ReadConnectionTokenSets(properties);
                var match = ConnectionTokenSetHelpers.FindConnectionTokenSet(sets, request.Connection, loginHint);
                if (match != null && match.ExpiresAt > DateTimeOffset.UtcNow.Add(optionsWithAccessToken.AccessTokenExpirationLeeway).ToUnixTimeSeconds())
                {
                    return match.AccessToken;
                }
            }

            // 2. A federated connection token can only be obtained via the refresh token.
            if (!properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken) || string.IsNullOrWhiteSpace(refreshToken))
            {
                if (optionsWithAccessToken.Events?.OnMissingRefreshToken != null)
                {
                    await optionsWithAccessToken.Events.OnMissingRefreshToken(context).ConfigureAwait(false);
                }

                return null;
            }

            var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
            var tokenClient = new TokenClient(
                httpClient,
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.Auth0MtlsEndpointResolver>(),
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector>());
            var resolvedDomain = context.GetResolvedDomain();

            TokenRefreshResult result;
            try
            {
                result = await tokenClient.ExchangeRefreshTokenForConnectionToken(options, refreshToken, request.Connection, resolvedDomain, loginHint).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await FireRefreshFailed(optionsWithAccessToken,
                    AccessTokenRefreshFailedContext.FromException(context, null, null, ex)).ConfigureAwait(false);
                return null;
            }

            if (!result.IsSuccess)
            {
                await FireRefreshFailed(optionsWithAccessToken,
                    AccessTokenRefreshFailedContext.FromHttpRejection(context, null, null, result.StatusCode, result.Error, result.ErrorDescription)).ConfigureAwait(false);
                return null;
            }

            var response = result.Response!;

            // 3. Cache the connection token and persist. A rotated refresh token, if any, is also persisted.
            var updated = ConnectionTokenSetHelpers.UpsertConnectionTokenSet(ReadConnectionTokenSets(properties), request.Connection, response, loginHint);
            WriteConnectionTokenSets(properties, updated);

            if (!string.IsNullOrEmpty(response.RefreshToken))
            {
                properties.UpdateTokenValue("refresh_token", response.RefreshToken);
            }

            await context.SignInAsync(options.CookieAuthenticationScheme, authenticateResult.Principal!, properties).ConfigureAwait(false);

            return response.AccessToken;
        }

        /// <summary>
        /// Performs a Custom Token Exchange : exchanges the external token described by
        /// <paramref name="request"/> for Auth0 tokens, without a browser redirect. This is the
        /// stateless utility - it has <b>no session side-effects</b> (it does not sign the user in or
        /// write any cookie); the caller decides what to persist. Use it for delegation/impersonation
        /// and agent-identity scenarios.
        /// </summary>
        /// <param name="context">The current <see cref="HttpContext"/>.</param>
        /// <param name="request">The exchange request (subject token + type, and optional audience,
        /// scope, actor token pair, organization).</param>
        /// <param name="scheme">The Auth0 authentication scheme. Defaults to <see cref="Auth0Constants.AuthenticationScheme"/>.</param>
        /// <returns>The exchanged tokens.</returns>
        /// <exception cref="CustomTokenExchangeException">
        /// Thrown when the request fails client-side validation, or when the token endpoint rejects
        /// the exchange.
        /// </exception>
        public static async Task<CustomTokenExchangeResult> CustomTokenExchangeAsync(this HttpContext context, CustomTokenExchangeRequest request, string? scheme = null)
        {
            scheme ??= Auth0Constants.AuthenticationScheme;

            CustomTokenExchangeRequestValidator.Validate(request);

            var options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(scheme);

            var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
            var tokenClient = new TokenClient(
                httpClient,
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.Auth0MtlsEndpointResolver>(),
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector>());
            var resolvedDomain = context.GetResolvedDomain();

            var result = await tokenClient.ExchangeCustomToken(
                options,
                request.SubjectToken,
                request.SubjectTokenType,
                request.Audience,
                request.Scope,
                request.ActorToken,
                request.ActorTokenType,
                request.Organization,
                resolvedDomain).ConfigureAwait(false);

            if (!result.IsSuccess)
            {
                throw new CustomTokenExchangeException(result.StatusCode, result.Error, result.ErrorDescription);
            }

            var response = result.Response!;

            if (!string.IsNullOrWhiteSpace(request.Organization))
            {
                OrganizationClaimValidator.Validate(response.IdToken, request.Organization!);
            }

            return new CustomTokenExchangeResult
            {
                AccessToken = response.AccessToken,
                IdToken = response.IdToken,
                RefreshToken = response.RefreshToken,
                ExpiresIn = response.ExpiresIn,
                Scope = response.Scope,
                Act = ActClaimReader.TryRead(response.IdToken)
            };
        }

        /// <summary>
        /// Retrieves the upstream-IdP session ceiling (<c>session_expiry</c>, Unix seconds) that the
        /// SDK persisted on the session at login, when the connection emitted one. This reads the exact
        /// value the SDK enforces internally — the persisted session item, not the ID token claim — so
        /// the read-back stays consistent with enforcement even after a token refresh that does not
        /// re-emit the claim. Use it for app-level logic such as a session countdown. Returns
        /// <c>null</c> when there is no persisted ceiling or the user is not authenticated.
        /// </summary>
        /// <param name="context">The current <see cref="HttpContext"/>.</param>
        /// <param name="scheme">The Auth0 authentication scheme. Defaults to <see cref="Auth0Constants.AuthenticationScheme"/>.</param>
        /// <returns>The session ceiling in Unix seconds, or <c>null</c> when there is none.</returns>
        public static async Task<long?> GetSessionExpiryAsync(this HttpContext context, string? scheme = null)
        {
            scheme ??= Auth0Constants.AuthenticationScheme;

            var options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(scheme);

            var authenticateResult = await context.AuthenticateAsync(options.CookieAuthenticationScheme).ConfigureAwait(false);
            if (!authenticateResult.Succeeded || authenticateResult.Properties == null)
            {
                return null;
            }

            return SessionExpiryHelpers.TryGetPersistedCeiling(authenticateResult.Properties, out var seconds)
                ? seconds
                : (long?)null;
        }

        /// <summary>
        /// Requests a Session Transfer Token (STT) via Custom Token Exchange: exchanges the customer
        /// <see cref="SessionTransferTokenRequest.SubjectToken"/> for a short-lived, single-use STT
        /// that can be placed on a redirect to a target app (see
        /// <see cref="BuildSessionTransferRedirect"/>). The actor (the agent) is auto-sourced from the
        /// current session's id_token unless an explicit <see cref="SessionTransferTokenRequest.ActorToken"/>
        /// is supplied. The audience is set by the SDK to <c>urn:{resolved-domain}:session_transfer</c>.
        /// <para>
        /// The STT is <b>never persisted</b>. Auto-sourcing the actor may, however, refresh and persist
        /// the agent's session id_token when it is stale - identical to
        /// <see cref="GetAccessTokenAsync"/> and required for refresh-token rotation safety. How close to
        /// its <c>exp</c> the id_token must be to count as stale is governed by
        /// <see cref="Auth0WebAppWithAccessTokenOptions.AccessTokenExpirationLeeway"/>, which the SDK uses
        /// as its single expiry margin rather than exposing a separate id_token setting.
        /// </para>
        /// <para>
        /// <b>Enable <see cref="Auth0WebAppWithAccessTokenOptions.UseRefreshTokens"/>.</b> It defaults to
        /// <c>false</c>, and without it the session carries no <c>.Token.refresh_token</c>, so a stale
        /// id_token cannot be refreshed and this method throws
        /// <see cref="CustomTokenExchangeErrorCode.ActorUnavailable"/>.
        /// </para>
        /// </summary>
        /// <remarks>
        /// This method is not safe to call concurrently for the same session. When the actor is
        /// auto-sourced and the session id_token is stale, it performs the same read, refresh and
        /// <see cref="AuthenticationHttpContextExtensions.SignInAsync(HttpContext, string?, System.Security.Claims.ClaimsPrincipal, AuthenticationProperties?)"/>
        /// sequence as <see cref="GetAccessTokenAsync"/>, and carries the same hazard.
        /// <para>
        /// To avoid it, ensure only one call that may refresh the session is in flight per session at a
        /// time - counting <see cref="GetAccessTokenAsync"/> and
        /// <see cref="GetAccessTokenForConnectionAsync"/> as well, since they share the same session
        /// slots. Either don't issue such requests in parallel, or plug in a server-side session store via
        /// <see cref="Auth0WebAppAuthenticationBuilder.WithSessionStore(Microsoft.AspNetCore.Authentication.Cookies.ITicketStore)"/>
        /// whose <c>ITicketStore</c> serializes concurrent access per session. Passing an explicit
        /// <see cref="SessionTransferTokenRequest.ActorToken"/> skips the refresh path entirely and avoids
        /// the hazard.
        /// </para>
        /// </remarks>
        /// <param name="context">The current <see cref="HttpContext"/>.</param>
        /// <param name="request">The session-transfer request (subject token + type, optional explicit
        /// actor pair, organization, scope).</param>
        /// <param name="scheme">The Auth0 authentication scheme. Defaults to <see cref="Auth0Constants.AuthenticationScheme"/>.</param>
        /// <returns>The issued Session Transfer Token and metadata.</returns>
        /// <exception cref="CustomTokenExchangeException">
        /// Thrown on client-side validation failure; when an explicit actor is blank, untrimmed or
        /// <c>"Bearer "</c>-prefixed, or when <see cref="SessionTransferTokenRequest.ActorTokenType"/> is
        /// set without an <see cref="SessionTransferTokenRequest.ActorToken"/>
        /// (<see cref="CustomTokenExchangeErrorCode.InvalidTokenFormat"/>); when no actor can be
        /// resolved (<see cref="CustomTokenExchangeErrorCode.ActorUnavailable"/>); when the token
        /// endpoint rejects the exchange (carrying the raw status/error/error_description, plus
        /// <see cref="CustomTokenExchangeException.Code"/> when the server's <c>error</c> maps onto
        /// <see cref="CustomTokenExchangeErrorCode.SetActorRequired"/> or
        /// <see cref="CustomTokenExchangeErrorCode.SessionTransferDisabled"/> - Auth0 reports both as a
        /// generic <c>invalid_request</c> today, so match on
        /// <see cref="CustomTokenExchangeException.ErrorDescription"/> for now); or when it
        /// returns 200 without <c>issued_token_type</c> set to
        /// <see cref="Auth0Constants.SessionTransferTokenType"/> (<see cref="CustomTokenExchangeException.Error"/>
        /// is <c>invalid_issued_token_type</c>), which indicates the CTE profile or client is not
        /// configured for session transfer. Also thrown when a transport error prevents reaching the
        /// token endpoint - either on the actor refresh or on the exchange itself - with the original
        /// <see cref="System.Net.Http.HttpRequestException"/> / <see cref="System.Threading.Tasks.TaskCanceledException"/>
        /// preserved on <see cref="System.Exception.InnerException"/>.
        /// </exception>
        /// <exception cref="MfaRequiredException">
        /// Thrown when auto-sourcing the actor requires refreshing a stale session id_token and that
        /// refresh returns <c>mfa_required</c> with an <c>mfa_token</c>. This is a recoverable step-up
        /// challenge rather than an unresolvable actor: drive the challenge/verify flow with
        /// <see cref="AuthenticationApi.IAuthenticationApiClient"/> using the
        /// <see cref="MfaRequiredException.MfaToken"/> blob, then pass the <c>id_token</c> from the
        /// completed grant back as <see cref="SessionTransferTokenRequest.ActorToken"/> and retry.
        /// The actor refresh binds the <c>openid</c> scope into the blob so the MFA grant returns one.
        /// An <c>mfa_required</c> response with no <c>mfa_token</c> cannot drive the flow and falls
        /// through to <see cref="CustomTokenExchangeErrorCode.ActorUnavailable"/> instead.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// Thrown when auto-sourcing the actor refreshes a stale session id_token but the rotated
        /// session cannot be persisted because the response has already started. Persisting calls
        /// <see cref="AuthenticationHttpContextExtensions.SignInAsync(HttpContext, string?, System.Security.Claims.ClaimsPrincipal, AuthenticationProperties?)"/>,
        /// which writes the authentication cookie; if the headers have already been sent, this throws
        /// and the exception propagates out of this method (identical to <see cref="GetAccessTokenAsync"/>).
        /// </exception>
        public static async Task<SessionTransferTokenResult> RequestSessionTransferTokenAsync(this HttpContext context, SessionTransferTokenRequest request, string? scheme = null)
        {
            scheme ??= Auth0Constants.AuthenticationScheme;

            // Reuse the existing CTE subject-token validation (empty / whitespace / "Bearer " prefix).
            CustomTokenExchangeRequestValidator.Validate(new CustomTokenExchangeRequest
            {
                SubjectToken = request.SubjectToken,
                SubjectTokenType = request.SubjectTokenType
            });

            var options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(scheme);
            var optionsWithAccessToken = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(scheme);

            var (actorToken, actorTokenType) = await ResolveActorTokenAsync(context, request, options, optionsWithAccessToken).ConfigureAwait(false);

            var resolvedDomain = context.GetResolvedDomain();

            // The audience must carry the bare host. A DomainResolver may return either a bare host
            // ("tenant.custom.com") or a full issuer ("https://tenant.custom.com/") - both shapes are
            // supported and Auth0CustomDomainStartupFilter stores whichever it gets verbatim in
            // HttpContext.Items - so interpolating the raw value would yield
            // urn:https://tenant.custom.com:session_transfer. Normalizing through Utils.ToAuthority
            // first is how the rest of the SDK consumes this value (see
            // Auth0CustomDomainsOpenIdConnectConfigurationManager and BackchannelLogoutHandler).
            var audienceHost = new Uri(Utils.ToAuthority(resolvedDomain ?? options.Domain)).Host;
            var audience = $"urn:{audienceHost}:session_transfer";

            var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
            var tokenClient = new TokenClient(
                httpClient,
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.Auth0MtlsEndpointResolver>(),
                context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector>());

            TokenRefreshResult result;
            try
            {
                result = await tokenClient.ExchangeCustomToken(
                    options,
                    request.SubjectToken,
                    request.SubjectTokenType,
                    audience,
                    request.Scope,
                    actorToken,
                    actorTokenType,
                    request.Organization,
                    resolvedDomain).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Keep a single failure protocol: a transport error reaching the token endpoint is
                // reported the same way as a rejection by it, with the original exception preserved
                // on InnerException.
                throw new CustomTokenExchangeException(
                    "The session transfer token exchange could not reach the token endpoint.", ex);
            }

            if (!result.IsSuccess)
            {
                // The raw error/error_description are always preserved; Code is additionally set when
                // the server's error field is one the SDK recognises, so a caller can match on
                // CustomTokenExchangeErrorCode instead of parsing text. Null today - Auth0 reports both
                // session-transfer rejections as a generic invalid_request.
                throw new CustomTokenExchangeException(
                    result.StatusCode,
                    result.Error,
                    result.ErrorDescription,
                    CustomTokenExchangeErrorCode.MapServerError(result.Error));
            }

            var response = result.Response!;


            // A CTE profile that is not set up for session transfer
            // returns an ordinary, long-lived, multi-use access token through this exact path.
            // A tenant misconfiguration must surface as an error.
            if (!string.Equals(response.IssuedTokenType, Auth0Constants.SessionTransferTokenType, StringComparison.Ordinal))
            {
                throw new CustomTokenExchangeException(
                    result.StatusCode,
                    "invalid_issued_token_type",
                    $"The token endpoint did not return a session transfer token.");
            }

            // The STT is returned in the access_token field. It is surfaced to the caller and never persisted.
            return new SessionTransferTokenResult
            {
                SessionTransferToken = response.AccessToken,
                IssuedTokenType = response.IssuedTokenType!,
                ExpiresIn = response.ExpiresIn,
                TokenType = response.TokenType,
                Scope = response.Scope
            };
        }

        /// <summary>
        /// Resolves the actor token for a session-transfer exchange. Explicit actor wins; otherwise the
        /// session id_token is used when fresh, refreshed when stale (persisting the rotated session),
        /// and <see cref="CustomTokenExchangeErrorCode.ActorUnavailable"/> is thrown when nothing is
        /// resolvable - before any STT exchange call.
        /// </summary>
        private static async Task<(string ActorToken, string ActorTokenType)> ResolveActorTokenAsync(
            HttpContext context,
            SessionTransferTokenRequest request,
            Auth0WebAppOptions options,
            Auth0WebAppWithAccessTokenOptions optionsWithAccessToken)
        {
            if (request.ActorToken != null)
            {
                return SessionTransferActorResolver.ResolveExplicitActor(request.ActorToken, request.ActorTokenType);
            }

            // An ActorTokenType with no ActorToken cannot be honoured
            if (!string.IsNullOrWhiteSpace(request.ActorTokenType))
            {
                throw new CustomTokenExchangeException(
                    CustomTokenExchangeErrorCode.InvalidTokenFormat,
                    "ActorTokenType was provided without an ActorToken. Supply both to use an explicit actor");
            }

            var authenticateResult = await context.AuthenticateAsync(options.CookieAuthenticationScheme).ConfigureAwait(false);
            if (!authenticateResult.Succeeded || authenticateResult.Properties == null)
            {
                throw new CustomTokenExchangeException(
                    CustomTokenExchangeErrorCode.ActorUnavailable,
                    "No authenticated session is available to source the actor token.");
            }

            var properties = authenticateResult.Properties;
            properties.Items.TryGetValue(".Token.id_token", out var idToken);

            // AccessTokenExpirationLeeway is reused for the id_token deliberately, rather than given a
            // dedicated option.
            // AuthenticationBuilderExtensions.RefreshTokenIfNeccesary applies it to a refresh that
            // rotates the stored id_token alongside the access token, so it governs id_token freshness
            // on the cookie-validation path too. If a caller ever needs them to differ, they can pass an explicit ActorToken.
            var leeway = optionsWithAccessToken.AccessTokenExpirationLeeway;
            if (SessionTransferActorResolver.IsIdTokenFresh(idToken, leeway))
            {
                return (idToken!, Auth0Constants.IdTokenType);
            }

            // Stale/missing id_token - try to refresh via the session refresh token (rotation-safe).
            if (properties.Items.TryGetValue(".Token.refresh_token", out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken))
            {
                var httpClient = options.Backchannel ?? context.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
                var tokenClient = new TokenClient(
                    httpClient,
                    context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.Auth0MtlsEndpointResolver>(),
                    context.RequestServices.GetService<Auth0.AspNetCore.Authentication.Mtls.MtlsCnfInspector>());
                var resolvedDomain = context.GetResolvedDomain();

                const string actorRefreshScope = "openid";

                TokenRefreshResult refreshResult;
                try
                {
                    refreshResult = await tokenClient.Refresh(options, refreshToken!, resolvedDomain, scope: actorRefreshScope).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // Transport errors (HttpRequestException, TaskCanceledException) would otherwise
                    // escape raw from a method documented to fail via CustomTokenExchangeException.
                    // ActorUnavailable would be a lie here - the session is fine, the network was not.
                    throw new CustomTokenExchangeException(
                        "Failed to refresh the session id_token needed to source the actor token.", ex);
                }

                // A step-up challenge is a recoverable case distinct from "no usable actor": collapsing
                // it into ActorUnavailable would tell the agent its session has no refresh token, which
                // is false, and leave no path to complete MFA and retry.
                if (!refreshResult.IsSuccess &&
                    refreshResult.Error == "mfa_required" &&
                    !string.IsNullOrEmpty(refreshResult.MfaToken))
                {
                    var protector = context.RequestServices.GetRequiredService<IMfaTokenProtector>();
                    var blob = protector.Protect(new MfaTokenContext
                    {
                        MfaToken = refreshResult.MfaToken!,
                        Audience = null,
                        Scope = actorRefreshScope,
                        MfaRequirements = refreshResult.MfaRequirements
                    });

                    throw new MfaRequiredException(
                        blob,
                        refreshResult.MfaRequirements,
                        (HttpStatusCode)(refreshResult.StatusCode ?? (int)HttpStatusCode.Forbidden),
                        new Exceptions.ApiError { Error = refreshResult.Error, Message = refreshResult.ErrorDescription ?? string.Empty });
                }

                if (refreshResult.IsSuccess && !string.IsNullOrEmpty(refreshResult.Response!.IdToken))
                {
                    var response = refreshResult.Response!;

                    // Only the id_token (and a rotated refresh token) are persisted. The primary
                    // .Token.access_token / .Token.expires_at slots are deliberately left alone:
                    // this refresh requests no audience or scope, so the access token it returns is
                    // for the tenant default rather than the application's configured audience -
                    // exactly the contract MatchesPrimaryToken and IsPrimaryExpired rely on.
                    // Writing it (and resetting expires_at to a full fresh lifetime) would make the
                    // next GetAccessTokenAsync serve a wrong-audience token from cache, and the reset
                    // expiry would keep it doing so for that whole lifetime.
                    //
                    // Assigned directly rather than via UpdateTokenValue, which only writes a key
                    // that is already present: a session with no stored id_token would otherwise
                    // no-op here and persist nothing, burning a refresh-token rotation per call.
                    properties.Items[".Token.id_token"] = response.IdToken;

                    if (!string.IsNullOrEmpty(response.RefreshToken))
                    {
                        properties.UpdateTokenValue("refresh_token", response.RefreshToken);
                    }

                    await context.SignInAsync(options.CookieAuthenticationScheme, authenticateResult.Principal!, properties).ConfigureAwait(false);

                    return (response.IdToken, Auth0Constants.IdTokenType);
                }
            }

            // UseRefreshTokens defaults to false, so "no refresh token" is the SDK's out-of-the-box
            // state rather than an unusual one. Naming the option here means the exception explains
            // its own most likely cause instead of reading as an unrecoverable session problem.
            throw new CustomTokenExchangeException(
                CustomTokenExchangeErrorCode.ActorUnavailable,
                "Could not source an actor token: the session has no usable id_token and no refresh token to obtain one. " +
                "Enable refresh tokens with .WithAccessToken(o => o.UseRefreshTokens = true) so a stale id_token can be " +
                "refreshed, or pass an explicit ActorToken on the request.");
        }

        /// <summary>
        /// Builds the redirect URL that carries a Session Transfer Token to a target app's login
        /// endpoint. Appends <c>session_transfer_token</c> (URL-encoded) to <paramref name="targetLoginUrl"/>,
        /// preserving any existing query, and appends <c>organization</c> when supplied. Performs no
        /// network call and writes nothing.
        /// </summary>
        /// <remarks>
        /// Returns a <see cref="string"/> rather than an <c>IActionResult</c> so the same helper works
        /// in Minimal APIs (<c>Results.Redirect(url)</c>) and MVC (<c>Redirect(url)</c>) - an
        /// <c>IActionResult</c> would not compose with a Minimal API endpoint return.
        /// <para>
        /// <b>Security:</b> <paramref name="targetLoginUrl"/> must be app-controlled - the STT is a live
        /// credential. The URL must be absolute HTTPS; a relative or non-HTTPS target throws.
        /// </para>
        /// This is kept as an <see cref="HttpContext"/> extension (though it does not read the context)
        /// so it sits discoverably alongside <see cref="RequestSessionTransferTokenAsync"/>.
        /// </remarks>
        /// <param name="context">The current <see cref="HttpContext"/> (unused; present for a consistent surface).</param>
        /// <param name="targetLoginUrl">The target app's login URL. Must be an absolute HTTPS URI.</param>
        /// <param name="result">The result from <see cref="RequestSessionTransferTokenAsync"/>.</param>
        /// <param name="organization">Optional organization ID/name to forward to the target.</param>
        /// <returns>The absolute redirect URL carrying the STT.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="targetLoginUrl"/> is not an absolute HTTPS URI.</exception>
        public static string BuildSessionTransferRedirect(this HttpContext context, string targetLoginUrl, SessionTransferTokenResult result, string? organization = null)
        {
            if (!Uri.TryCreate(targetLoginUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException(
                    "targetLoginUrl must be an absolute HTTPS URL.", nameof(targetLoginUrl));
            }

            // Split off any fragment so the query is inserted before it. Appending to the raw
            // string would place session_transfer_token after '#', where the browser never
            // transmits it and the STT silently never reaches the target.
            var hashIndex = targetLoginUrl.IndexOf('#');
            var baseUrl = hashIndex >= 0 ? targetLoginUrl.Substring(0, hashIndex) : targetLoginUrl;
            var fragment = hashIndex >= 0 ? targetLoginUrl.Substring(hashIndex) : string.Empty;

            var separator = string.IsNullOrEmpty(uri.Query) ? "?" : "&";
            var builder = new System.Text.StringBuilder(baseUrl);
            builder.Append(separator);
            builder.Append("session_transfer_token=");
            builder.Append(Uri.EscapeDataString(result.SessionTransferToken));

            if (!string.IsNullOrWhiteSpace(organization))
            {
                builder.Append("&organization=");
                builder.Append(Uri.EscapeDataString(organization!));
            }

            builder.Append(fragment);

            return builder.ToString();
        }

        /// <summary>
        /// Builds the redirect URL that carries a Session Transfer Token to a target app's login
        /// endpoint, taking the <c>organization</c> from the same <paramref name="request"/> that was
        /// exchanged. Prefer this overload when the exchange was organization-scoped: the request stays
        /// the single source of truth, so the redirect cannot silently disagree with the exchange.
        /// </summary>
        /// <param name="context">The current <see cref="HttpContext"/> (unused; present for a consistent surface).</param>
        /// <param name="targetLoginUrl">The target app's login URL. Must be an absolute HTTPS URI.</param>
        /// <param name="result">The result from <see cref="RequestSessionTransferTokenAsync"/>.</param>
        /// <param name="request">The request that produced <paramref name="result"/>; its
        /// <see cref="SessionTransferTokenRequest.Organization"/> is forwarded to the target.</param>
        /// <returns>The absolute redirect URL carrying the STT.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="targetLoginUrl"/> is not an absolute HTTPS URI.</exception>
        public static string BuildSessionTransferRedirect(this HttpContext context, string targetLoginUrl, SessionTransferTokenResult result, SessionTransferTokenRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            return context.BuildSessionTransferRedirect(targetLoginUrl, result, request.Organization);
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
        /// (login-time) token - the one stored in the <c>.Token.access_token</c> slot - rather
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

        private static List<ConnectionTokenSet> ReadConnectionTokenSets(AuthenticationProperties properties)
        {
            if (properties.Items.TryGetValue(ConnectionTokensItemKey, out var json) && !string.IsNullOrEmpty(json))
            {
                // Corrupted or version-skewed session data is treated as a cache miss: the
                // token gets re-fetched, which is preferable to throwing out of a public method.
                try
                {
                    return JsonSerializer.Deserialize<List<ConnectionTokenSet>>(json) ?? new List<ConnectionTokenSet>();
                }
                catch (JsonException)
                {
                    return new List<ConnectionTokenSet>();
                }
            }

            return new List<ConnectionTokenSet>();
        }

        private static void WriteConnectionTokenSets(AuthenticationProperties properties, List<ConnectionTokenSet> sets)
        {
            properties.Items[ConnectionTokensItemKey] = JsonSerializer.Serialize(sets);
        }
    }
}
