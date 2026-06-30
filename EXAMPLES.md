# Examples using auth0-aspnetcore-authentication

- [Login and Logout](#login-and-logout)
- [Scopes](#scopes)
- [Calling an API](#calling-an-api)
  - [Configuring the refresh leeway](#configuring-the-refresh-leeway)
  - [Updating claims and observing a successful refresh](#updating-claims-and-observing-a-successful-refresh)
- [Server-side session storage](#server-side-session-storage)
- [Multi-Resource Refresh Tokens (MRRT)](#multi-resource-refresh-tokens-mrrt)
  - [Requesting a token for another audience](#requesting-a-token-for-another-audience)
  - [Configuring default scopes per audience](#configuring-default-scopes-per-audience)
  - [Forcing a refresh](#forcing-a-refresh)
  - [Handling refresh failures](#handling-refresh-failures)
  - [Handling MFA during token exchange (mfa_required)](#handling-mfa-during-token-exchange-mfa_required)
    - [Completing an out-of-band (OOB) challenge with polling](#completing-an-out-of-band-oob-challenge-with-polling)
- [Token Vault (Federated Connection Access Tokens)](#token-vault-federated-connection-access-tokens)
  - [Retrieving a federated connection token](#retrieving-a-federated-connection-token)
  - [Forcing a refresh](#forcing-a-refresh-1)
  - [Handling a missing refresh token or exchange failure](#handling-a-missing-refresh-token-or-exchange-failure)
- [Custom Token Exchange](#custom-token-exchange)
  - [Delegation / impersonation](#delegation--impersonation)
- [Organizations](#organizations)
- [Extra parameters](#extra-parameters)
- [Roles](#roles)
- [Multiple Custom Domain (MCD) Support](#multiple-custom-domain-mcd-support)
- [Backchannel Logout](#backchannel-logout)
- [Blazor Server](#blazor-server)

## Login and Logout
Triggering login or logout is done using ASP.NET's `HttpContext`:

```csharp
public async Task Login(string returnUrl = "/")
{
    var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
        .WithRedirectUri(returnUrl)
        .Build();

    await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
}

[Authorize]
public async Task Logout()
{
    var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
        // Indicate here where Auth0 should redirect the user after a logout.
        // Note that the resulting absolute Uri must be added in the
        // **Allowed Logout URLs** settings for the client.
        .WithRedirectUri(Url.Action("Index", "Home"))
        .Build();

    await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
```

## Scopes

By default, this SDK requests the `openid profile` scopes, if needed you can configure the SDK to request a different set of scopes.
As `openid` is a [required scope](https://auth0.com/docs/scopes/openid-connect-scopes), the SDK will ensure the `openid` scope is always added, even when explicitly omitted when setting the scope.

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Scope = "openid profile scope1 scope2";
});
```

Apart from being able to configure the used scopes globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply scopes when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithScope("openid profile scope1 scope2")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the scopes when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured scopes.

## Calling an API

If you want to call an API from your ASP.NET MVC application, you need to obtain an access token issued for the API you want to call. 
As the SDK is configured to use OAuth's [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post), no access token will be returned by default. In order to do so, we should be using the [Authorization Code Grant](https://auth0.com/docs/flows/authorization-code-flow), which requires the use of a `ClientSecret`.
Next, to obtain the token to access an external API, call `WithAccessToken` and set the `audience` to the API Identifier. You can get the API Identifier from the API Settings for the API you want to use.

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
    });
```

Apart from being able to configure the audience globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply the audience when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithRedirectUri("/") // "/" is the default value used for RedirectUri, so this can be omitted.
    .WithAudience("YOUR_AUDIENCE")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the Audience when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Audience.

### Retrieving the access token

As the SDK uses the OpenId Connect middleware, the ID token is decoded and the corresponding claims are added to the `ClaimsIdentity`, making them available by using `User.Claims`.

The access token can be retrieved by calling `HttpContext.GetTokenAsync("access_token")`.

```csharp
[Authorize]
public async Task<IActionResult> Profile()
{
    var accessToken = await HttpContext.GetTokenAsync("access_token");

    return View(new UserProfileViewModel()
    {
        Name = User.Identity.Name,
        EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
        ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
    });
}
```

### Refresh tokens

In the case where the application needs to use an access token to access an API, there may be a situation where the access token expires before the application's session does. In order to ensure you have a valid access token at all times, you can configure the SDK to use refresh tokens:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuth0WebAppAuthentication(options =>
        {
            options.Domain = Configuration["Auth0:Domain"];
            options.ClientId = Configuration["Auth0:ClientId"];
            options.ClientSecret = Configuration["Auth0:ClientSecret"];
        })
        .WithAccessToken(options =>
        {
            options.Audience = Configuration["Auth0:Audience"];
            options.UseRefreshTokens = true;
        });
}
```

#### Configuring the refresh leeway

When refresh tokens are enabled, the SDK refreshes the access token slightly *before* it actually expires, so a request in flight isn't left holding a token that lapses mid-call. This window defaults to **60 seconds**. You can tune it with `AccessTokenExpirationLeeway`:

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        // Refresh the access token up to 2 minutes before it expires.
        options.AccessTokenExpirationLeeway = TimeSpan.FromSeconds(120);
    });
```

A larger leeway refreshes more eagerly (fewer near-expiry tokens, more refresh calls); a smaller leeway refreshes later. The leeway only takes effect when `UseRefreshTokens` is enabled.

> :information_source: To obtain access tokens for **additional** audiences or scopes on demand (without a second login), see [Multi-Resource Refresh Tokens (MRRT)](#multi-resource-refresh-tokens-mrrt).

#### Detecting the absense of a refresh token

In the event where the API, defined in your Auth0 dashboard, isn't configured to [allow offline access](https://auth0.com/docs/get-started/dashboard/api-settings), or the user was already logged in before the use of refresh tokens was enabled (e.g. a user logs in a few minutes before the use of refresh tokens is deployed), it might be useful to detect the absense of a refresh token in order to react accordingly (e.g. log the user out locally and force them to re-login).

```
services
    .AddAuth0WebAppAuthentication(options => {})
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        options.Events = new Auth0WebAppWithAccessTokenEvents
        {
            OnMissingRefreshToken = async (context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                var authenticationProperties = new LogoutAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            }
        };
    });
```

The above snippet checks whether the SDK is configured to use refresh tokens, if there is an existing ID token (meaning the user is authenticated) as well as the absence of a refresh token. If each of these criteria are met, it logs the user out from the application and initializes a new login flow.

> :information_source: In order for Auth0 to redirect back to the application's login URL, ensure to add the configured redirect URL to the application's `Allowed Logout URLs` in Auth0's dashboard.

#### Updating claims and observing a successful refresh

When the SDK refreshes an expired access token, it persists the new tokens but, by default, leaves the `ClaimsPrincipal` untouched — so `User.Claims` keeps serving the login-time snapshot for the lifetime of the refresh token, even though each refresh can return a fresh `id_token` that may carry updated user information.

Two opt-in additions let you react to a refresh:

- **`RebuildPrincipalOnRefresh`** — when `true`, the `ClaimsPrincipal` is rebuilt from the refreshed `id_token` after a successful primary refresh, so `User.Claims` (and `User.Identity.Name`) reflect current user information. Defaults to `false` (today's behavior).
- **`OnTokensRefreshed`** — a success event that fires after a successful primary refresh, carrying the refreshed `AccessToken`, `IdToken`, `RefreshToken` (null when not rotated), and `ExpiresAt`. It fires independently of `RebuildPrincipalOnRefresh`, and when both are used the event fires *after* the rebuild so it observes the updated principal.

```csharp
services
    .AddAuth0WebAppAuthentication(options => {})
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;

        // Rebuild User.Claims from the refreshed id_token.
        options.RebuildPrincipalOnRefresh = true;

        options.Events = new Auth0WebAppWithAccessTokenEvents
        {
            OnTokensRefreshed = (context) =>
            {
                // context.AccessToken, context.IdToken, context.RefreshToken, context.ExpiresAt
                return Task.CompletedTask;
            }
        };
    });
```

##### Controlling how the refreshed id_token is validated

`RefreshClaimsValidationType` controls how rigorously the refreshed `id_token` is validated before its claims replace the principal. It is only consulted when `RebuildPrincipalOnRefresh` is `true`:

- **`Full`** (default) — validates the refreshed `id_token`'s signature against the cached JWKS, plus issuer/audience and the SDK's business-rule checks. Highest fidelity. The signature check runs only on an actual refresh (when the token expired), not on every request, and the JWKS is cached, so it is inexpensive in the hot path.
- **`SkipSignature`** — skips signature validation (trusting the back-channel TLS exchange for token authenticity) while still running the SDK's business-rule checks. Lower cost, lower fidelity; an opt-in escape hatch.

```csharp
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        options.RebuildPrincipalOnRefresh = true;
        options.RefreshClaimsValidationType = RefreshClaimsValidationType.SkipSignature;
    });
```

If a refresh succeeds but rebuilding the principal fails (a signature failure in `Full` mode, a malformed `id_token`, or a business-rule failure), the SDK degrades gracefully: the refreshed tokens are kept, the existing (stale) principal is retained, a warning is logged, and `OnTokensRefreshed` still fires — the refresh genuinely succeeded.

> :information_source: Both additions apply only to the primary (login-time) refresh path. Tokens fetched for **additional** audiences via [MRRT](#multi-resource-refresh-tokens-mrrt) do not rebuild the principal or fire `OnTokensRefreshed`.

## Server-side session storage

By default, the SDK is **stateless**: the entire authentication session - the user's identity claims together with the ID, access, and refresh tokens - is serialized into the encrypted authentication cookie. This requires no additional infrastructure and lets any instance behind a load balancer serve any request.

Because everything lives in the cookie, the session is subject to the browser's cookie size limits (around 4 KB per cookie). ASP.NET Core automatically splits a larger payload across multiple cookies, but tokens are large and browsers/proxies also cap the total size of request headers. Sessions that accumulate several tokens can therefore grow large enough to be rejected by the browser, a reverse proxy, or the web server.

To avoid this, you can move the session **server-side**. The cookie then holds only a small session key, while the full session payload is kept in a store you control. Use `WithSessionStore` to provide an [`ITicketStore`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.iticketstore) implementation:

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
    })
    .WithSessionStore<RedisTicketStore>();
```

Server-side session storage is a built-in ASP.NET Core capability (`CookieAuthenticationOptions.SessionStore`), so this was always possible - but only by post-configuring the cookie options for the exact scheme the SDK uses internally. Getting that scheme name wrong left the store silently unused. `WithSessionStore` simply makes it easier: it attaches the store to the SDK's own cookie scheme for you, so it keeps working even when you set a custom `CookieAuthenticationScheme` - there is no scheme name to wire up by hand.

Keep the **default cookie-based session** when you want to stay stateless and avoid running extra infrastructure - for most applications it is the simplest and best choice. Server-side storage is an opt-in for the cases above, and it requires a store that is shared across all your instances (for example a distributed cache) when you run more than one.

### Providing the ITicketStore

You can pass either a type (resolved from the dependency injection container, so it may depend on other registered services such as `IDistributedCache` and `IDataProtectionProvider`) or an already-constructed instance:

```csharp
// Resolved from the container - supports constructor injection.
.WithSessionStore<RedisTicketStore>();

// Or supply an instance directly - you are then responsible for its dependencies.
.WithSessionStore(new RedisTicketStore(cache, dataProtectionProvider));
```

Prefer the type overload when your store depends on registered services (as the `RedisTicketStore` below does); the instance overload is best for stores you can construct by hand.

A minimal `IDistributedCache`-backed implementation looks like this. Honoring `ticket.Properties.ExpiresUtc` lets the cache expire abandoned sessions automatically. The serialized ticket contains the user's claims and any tokens (access/refresh) carried in `AuthenticationProperties`, so it is encrypted with an [`IDataProtector`](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/overview) before being written to the cache:

```csharp
public class RedisTicketStore : ITicketStore
{
    private readonly IDistributedCache _cache;
    private readonly IDataProtector _protector;

    public RedisTicketStore(IDistributedCache cache, IDataProtectionProvider provider)
    {
        _cache = cache;
        _protector = provider.CreateProtector("Auth0.AspNetCore.Authentication.RedisTicketStore");
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = $"auth-session-{Guid.NewGuid():N}";
        await RenewAsync(key, ticket);
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var options = new DistributedCacheEntryOptions { AbsoluteExpiration = ticket.Properties.ExpiresUtc };
        var payload = _protector.Protect(TicketSerializer.Default.Serialize(ticket));
        await _cache.SetAsync(key, payload, options);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await _cache.GetAsync(key);
        return bytes == null ? null : TicketSerializer.Default.Deserialize(_protector.Unprotect(bytes));
    }

    public Task RemoveAsync(string key) => _cache.RemoveAsync(key);
}
```

> :warning: **Running multiple instances:** the store must be shared across them (e.g. a distributed cache such as Redis or SQL Server). An in-memory store only works for a single instance and will cause users to appear logged out when their requests are served by a different instance. Likewise, the [Data Protection keys must be persisted and shared](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview) across all instances - otherwise tickets become unreadable after a key rotation, app restart, or when served by a different node.
>
> :warning: **Protecting the ticket:** it holds sensitive data (claims, access and refresh tokens). Encrypting the payload with `IDataProtector` as shown above means an attacker who gains read access to the cache cannot recover those tokens. Treat the cache backend itself as sensitive too: restrict access and enable encryption in transit (e.g. Redis AUTH + TLS) and at rest.

## Multi-Resource Refresh Tokens (MRRT)

[Multi-Resource Refresh Tokens (MRRT)](https://auth0.com/docs/secure/tokens/refresh-tokens/multi-resource-refresh-token) let a single session obtain access tokens for *additional* audiences and scopes on demand, by exchanging the session's refresh token — without forcing the user through another interactive login.

A typical use case: the user logs in once, and your web app then needs to call a downstream API that expects a token for a *different* audience than the one requested at login. Instead of re-authenticating, you exchange the existing refresh token for a token scoped to that API.

> :information_source: MRRT requires refresh tokens. Configure `UseRefreshTokens = true` and a `ClientSecret`, and ensure MRRT is enabled for your client/APIs in the Auth0 Dashboard. Tokens obtained for additional audiences are cached in the session alongside the login-time ("primary") token and reused until they near expiry.

> :warning: **Token storage and cookie size.** Each additional audience/scope you obtain a token for adds another entry to the cached token set, which by default is serialized into the encrypted **authentication cookie** along with the rest of the session. Cookies cannot grow indefinitely — browsers cap them at around 4 KB each, and request-header limits apply on top of that. An application that fans out across several audiences can therefore accumulate enough tokens to exceed those limits and have the session rejected. If you expect to hold tokens for more than a couple of audiences, move the session **server-side** so only a small session key rides in the cookie while the token set lives in a store you control — see [Server-side session storage](#server-side-session-storage) above. The MRRT API is identical either way; only where the token set is persisted changes.

### Requesting a token for another audience

Use `HttpContext.GetAccessTokenAsync` with an `AccessTokenRequest` describing the `Audience` and/or `Scope` you need. The SDK first tries to satisfy the request from the session (the primary token or a previously cached additional token), and only exchanges the refresh token when no usable cached token exists. Newly obtained tokens are persisted back into the session automatically.

```csharp
[Authorize]
public async Task<IActionResult> CallMessagesApi()
{
    var accessToken = await HttpContext.GetAccessTokenAsync(new AccessTokenRequest
    {
        Audience = "https://messages.example.com",
        Scope = "read:messages"
    });

    if (accessToken == null)
    {
        // No refresh token available, or the refresh failed — see "Handling refresh failures" below.
        return Challenge();
    }

    var request = new HttpRequestMessage(HttpMethod.Get, "https://messages.example.com/api/messages");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

    var response = await _httpClient.SendAsync(request);
    return Content(await response.Content.ReadAsStringAsync());
}
```

The requested `Scope` is merged (order-preserving union) with the configured default scopes for the resolved audience. Omitting `Audience` falls back to the globally configured `Audience`; omitting `Scope` falls back to the configured default for that audience.

> :information_source: `GetAccessTokenAsync` returns `null` rather than throwing when no refresh token is available or the refresh fails. Always check for `null` before using the token.

When called with no arguments matching the primary audience/scope, `GetAccessTokenAsync` is equivalent to retrieving the login-time access token (and refreshing it when expired).

### Configuring default scopes per audience

You can configure default scopes for each additional audience using `ScopeByAudience`. When an audience is present in this map, its value is used as the default scope for that audience; otherwise the global `Scope` is used as the fallback.

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        options.ScopeByAudience = new Dictionary<string, string>
        {
            ["https://messages.example.com"] = "read:messages write:messages",
            ["https://billing.example.com"]  = "read:invoices"
        };
    });
```

With this configured, a request for the `https://messages.example.com` audience defaults to the `read:messages write:messages` scopes, so callers can omit `Scope` for that audience:

```csharp
var accessToken = await HttpContext.GetAccessTokenAsync(new AccessTokenRequest
{
    Audience = "https://messages.example.com"
});
```

### Forcing a refresh

Set `ForceRefresh = true` to bypass the cache and always exchange the refresh token for a new access token. The freshly retrieved token still replaces the cached entry.

```csharp
var accessToken = await HttpContext.GetAccessTokenAsync(new AccessTokenRequest
{
    Audience = "https://messages.example.com",
    Scope = "read:messages",
    ForceRefresh = true
});
```

### Handling refresh failures

When a refresh token is present but the exchange fails, the `OnAccessTokenRefreshFailed` event fires and `GetAccessTokenAsync` returns `null`. The supplied `AccessTokenRefreshFailedContext` carries the failure details so you can distinguish a **terminal** failure (such as an `invalid_grant` for a revoked or expired refresh token, which warrants a re-login) from a **transient** one (such as a timeout or rate-limit, which may be retried).

All refresh failures — token-endpoint rejections, malformed responses, and transport/misconfiguration errors — flow through this single event. For HTTP rejections, `StatusCode`, `Error`, and `ErrorDescription` are populated; for transport failures, `Exception` is populated instead.

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        options.Events = new Auth0WebAppWithAccessTokenEvents
        {
            OnAccessTokenRefreshFailed = async (context) =>
            {
                // A revoked or expired refresh token is terminal — force a re-login.
                if (context.Error == "invalid_grant")
                {
                    await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    var authenticationProperties = new LogoutAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                    await context.HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
                }
                // Otherwise (e.g. a timeout surfaced via context.Exception, or a 429), you may
                // choose to log and let the caller retry.
            }
        };
    });
```

> :warning: `AccessTokenRefreshFailedContext.Exception` may contain transport/diagnostic detail — log it server-side only, do not surface it to end users.

### Handling MFA during token exchange (`mfa_required`)

When an access-token exchange (for example a Multi-Resource Refresh Token request via
`HttpContext.GetAccessTokenAsync`) returns an `mfa_required` error, the SDK throws an
`MfaRequiredException`. You drive the MFA challenge/verify flow with `IAuthenticationApiClient`
and decide what to do with the resulting tokens.

`ex.MfaToken` is an **opaque, encrypted token with a 5-minute lifetime** — the raw `mfa_token`
never leaves the SDK. Pass it back to the `IAuthenticationApiClient` methods unchanged; do not
inspect, parse, or store it long-term. `ex.MfaRequirements` describes the challenge types the
user can satisfy (for example `otp` or `oob`).

> :information_source: `MfaRequiredException` is raised by `GetAccessTokenAsync` whenever the
> exchange returns `mfa_required`, regardless of whether you called `WithAuthenticationApiClient()`.
> You still need `WithAuthenticationApiClient()` to register the `IAuthenticationApiClient` that
> *completes* the challenge — so register it whenever your tenant may return `mfa_required` on a
> refresh, otherwise you can catch the exception but have no client to drive the verify step.

#### Register the client

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.UseRefreshTokens = true;
    })
    .WithAuthenticationApiClient();
```

#### Catch `mfa_required`, challenge, and verify

```csharp
public class ResourceController : Controller
{
    private readonly IAuthenticationApiClient _authClient;

    public ResourceController(IAuthenticationApiClient authClient) => _authClient = authClient;

    public async Task<IActionResult> CallApi()
    {
        try
        {
            var accessToken = await HttpContext.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://my-second-api" });
            // ... use accessToken ...
            return Ok();
        }
        catch (MfaRequiredException ex)
        {
            // ex.MfaToken is an opaque, encrypted token valid for 5 minutes.
            // Inspect ex.MfaRequirements to discover which challenge types are available.
            var canUseOtp = ex.MfaRequirements?.Challenge?
                .Any(c => c.Type == "otp") ?? false;

            // Trigger a challenge (e.g. send an OTP / push). authenticatorId is optional.
            var challenge = await _authClient.MfaChallengeAsync(new MfaChallengeRequest
            {
                MfaToken = ex.MfaToken,
                ChallengeType = "otp"
            });

            // Store ex.MfaToken (and challenge.OobCode if using OOB) for the verify step,
            // then prompt the user for their code. The token expires 5 minutes after issue.
            TempData["mfa_token"] = ex.MfaToken;
            return RedirectToAction("EnterCode");
        }
    }

    [HttpPost]
    public async Task<IActionResult> EnterCode(string otp)
    {
        var mfaToken = (string)TempData["mfa_token"]!;

        try
        {
            var tokens = await _authClient.GetTokenAsync(new MfaOtpTokenRequest
            {
                MfaToken = mfaToken,
                Otp = otp
            });

            // tokens.AccessToken is now valid for the requested audience.
            // Persisting these tokens into the session is your responsibility — see below.
            return Ok();
        }
        catch (MfaTokenExpiredException)
        {
            // The 5-minute window elapsed — restart the flow to obtain a fresh token.
            return RedirectToAction("CallApi");
        }
        catch (MfaTokenInvalidException)
        {
            // The token was tampered with or malformed — restart the flow.
            return RedirectToAction("CallApi");
        }
    }
}
```

> :information_source: The SDK returns the MFA-grant tokens to you; it does not write them back
> into the authentication session automatically. If you want subsequent
> `GetAccessTokenAsync` calls to reuse them, persist them yourself — for example by updating
> the authentication properties and calling `HttpContext.SignInAsync(...)` with the updated
> principal.

A bad code (rejected by Auth0) surfaces as an `ErrorApiException` (with `StatusCode` and
`ApiError`), the base type of `MfaRequiredException`. A token that has passed its 5-minute
lifetime throws `MfaTokenExpiredException`; a tampered or malformed token throws
`MfaTokenInvalidException`. Both derive from `ErrorApiException`.

#### Completing an out-of-band (OOB) challenge with polling

Out-of-band factors (push notifications, SMS) are **asynchronous**: after you trigger the
challenge you must poll the token endpoint until the user approves it. Unlike the OTP grant, the
OOB grant does **not** throw while the user has not yet responded — Auth0 replies with
`authorization_pending` (or `slow_down` if you are polling too fast), and the SDK surfaces those
on `MfaOobTokenResponse.Error` so you can keep polling. A populated `AccessToken` (with
`Error == null`) means the challenge succeeded. Any genuine failure (for example an expired
`oob_code`) still throws `ErrorApiException`, just like the OTP grant.

```csharp
public async Task<IActionResult> StartOob()
{
    var mfaToken = (string)TempData["mfa_token"]!;

    // Trigger the push/SMS. The returned oob_code identifies this challenge.
    var challenge = await _authClient.MfaChallengeAsync(new MfaChallengeRequest
    {
        MfaToken = mfaToken,
        ChallengeType = "oob"
    });

    TempData["mfa_token"] = mfaToken;          // still needed for the verify step
    TempData["oob_code"] = challenge.OobCode;
    return RedirectToAction("PollOob");
}

[HttpPost]
public async Task<IActionResult> PollOob()
{
    var mfaToken = (string)TempData["mfa_token"]!;
    var oobCode = (string)TempData["oob_code"]!;

    try
    {
        var response = await _authClient.GetTokenAsync(new MfaOobTokenRequest
        {
            MfaToken = mfaToken,
            OobCode = oobCode
            // BindingCode = "1234"   // only when the challenge's binding_method requires it
        });

        if (response.Error == "authorization_pending" || response.Error == "slow_down")
        {
            // Not approved yet. Keep mfaToken/oobCode and poll again shortly. Back off a little
            // on slow_down. Remember the mfa_token's overall 5-minute lifetime still applies.
            TempData["mfa_token"] = mfaToken;
            TempData["oob_code"] = oobCode;
            return RedirectToAction("PollOob");
        }

        // response.Error is null here: the user approved and response.AccessToken is valid for
        // the requested audience. Persisting it into the session is your responsibility.
        return Ok();
    }
    catch (MfaTokenExpiredException)
    {
        // The 5-minute window elapsed — restart the flow to obtain a fresh token.
        return RedirectToAction("CallApi");
    }
    // A genuine rejection (e.g. invalid/expired oob_code) throws ErrorApiException.
}
```

> :information_source: The `mfa_token` blob is encrypted and **self-expires 5 minutes after the
> original `mfa_required`** — not after the challenge is triggered. Since OOB approval is
> user-paced, treat that window as your real polling budget: if it lapses, the next
> `GetTokenAsync` throws `MfaTokenExpiredException` before any network call, and you must restart
> from `GetAccessTokenAsync` to mint a fresh token.

> :warning: **Multi-instance deployments:** the encrypted `mfa_token` is protected with the
> application's ASP.NET Core Data Protection key ring. If your app runs on more than one
> instance, the key ring must be persisted and shared (for example with
> `PersistKeysToFileSystem` plus a `ProtectKeysWith*` provider, or a shared key store);
> otherwise a token encrypted on one instance cannot be decrypted on another within the
> 5-minute window. This is the **same requirement** as the authentication cookie that already
> carries these tokens.

## Token Vault (Federated Connection Access Tokens)

[Token Vault](https://auth0.com/docs/secure/tokens/token-vault) lets your web app obtain a **third-party API access token** (for a federated connection such as Google, GitHub, or Slack) for the logged-in user — so your app, or an agent acting on the user's behalf, can call that provider's API. The token is obtained by exchanging the session's refresh token; the user does not have to re-authenticate.

A typical use case: the user logged in with (or has linked) their Google account, and your app needs a Google access token to read their calendar. Instead of running a separate Google OAuth flow, you exchange the existing refresh token for a Google connection token.

> :information_source: Token Vault requires refresh tokens. Configure `UseRefreshTokens = true` and a `ClientSecret`, and enable Token Vault for the connection in the Auth0 Dashboard. Connection tokens are cached in the session, keyed by connection name, and reused until they near expiry.

> :information_source: Unlike MRRT, the federated-connection exchange does **not** take a requested `scope` — it returns the scopes already granted for the connection. Tokens are therefore cached per **connection**, not per audience/scope. To change the granted scopes, reconfigure the connection (or re-link the account) in the Auth0 Dashboard.

> :warning: **Token storage and cookie size.** Like MRRT, each connection token is cached in the encrypted **authentication cookie** by default, so retrieving tokens for several connections grows the session the same way fanning out across audiences does. If you expect to hold tokens for more than a couple of connections, move the session **server-side** — see [Server-side session storage](#server-side-session-storage). Where the token set is persisted is the only thing that changes; the API is identical either way.

### Retrieving a federated connection token

Use `HttpContext.GetAccessTokenForConnectionAsync` with an `AccessTokenForConnectionRequest` describing the `Connection`. The SDK serves a cached token from the session when one is present and unexpired, and only exchanges the refresh token otherwise. Newly obtained tokens are persisted back into the session automatically.

```csharp
[Authorize]
public async Task<IActionResult> CallGoogleCalendar()
{
    var googleToken = await HttpContext.GetAccessTokenForConnectionAsync(new AccessTokenForConnectionRequest
    {
        Connection = "google-oauth2"
    });

    if (googleToken == null)
    {
        // No refresh token available, or the exchange failed — see "Handling…" below.
        return Challenge();
    }

    var request = new HttpRequestMessage(HttpMethod.Get, "https://www.googleapis.com/calendar/v3/users/me/calendarList");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", googleToken);

    var response = await _httpClient.SendAsync(request);
    return Content(await response.Content.ReadAsStringAsync());
}
```

> :information_source: `GetAccessTokenForConnectionAsync` returns `null` rather than throwing when no refresh token is available or the exchange fails. Always check for `null` before using the token.

The optional `LoginHint` disambiguates which linked identity to use when the user has more than one. It is the **provider-side identity-provider user ID** (e.g. a Google user ID) — not the Auth0 user `sub`, and not the user's email.

`LoginHint` is part of the cache key: tokens for different login hints on the same connection are cached separately, so requesting identity B never returns identity A's cached token. A request with no `LoginHint` is cached separately from one that specifies a hint.

```csharp
var googleToken = await HttpContext.GetAccessTokenForConnectionAsync(new AccessTokenForConnectionRequest
{
    Connection = "google-oauth2",
    LoginHint = "108251234567890123456"
});
```

### Forcing a refresh

Set `ForceRefresh = true` to bypass the cache and always exchange the refresh token for a new connection token. The freshly retrieved token replaces the cached entry.

```csharp
var googleToken = await HttpContext.GetAccessTokenForConnectionAsync(new AccessTokenForConnectionRequest
{
    Connection = "google-oauth2",
    ForceRefresh = true
});
```

### Handling a missing refresh token or exchange failure

A federated connection token can only be obtained via the session's refresh token. When none is present, the `OnMissingRefreshToken` event fires and the method returns `null`. When a refresh token is present but the exchange is rejected, the `OnAccessTokenRefreshFailed` event fires (carrying `StatusCode`, `Error`, `ErrorDescription`) and the method returns `null`. These are the same events used by MRRT — see [Handling refresh failures](#handling-refresh-failures) and [Detecting the absense of a refresh token](#detecting-the-absense-of-a-refresh-token) for full configuration examples.

## Custom Token Exchange

[Custom Token Exchange](https://auth0.com/docs/authenticate/custom-token-exchange) (RFC 8693) exchanges an
existing external/custom security token for Auth0 tokens, without a browser redirect. Use it for
delegation/impersonation and agent-identity scenarios. It requires a configured Custom Token Exchange Profile
and a validation Action in your Auth0 tenant.

`CustomTokenExchangeAsync` is **stateless**: it performs the exchange and returns the tokens, but does **not**
sign the user in or write any cookie. The caller decides what to persist.

```csharp
try
{
    var result = await HttpContext.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
    {
        SubjectToken = externalToken,
        SubjectTokenType = "urn:acme:legacy-token", // a custom URI matching your CTE Profile
        Audience = "https://api.example.com",       // optional
        Scope = "read:data"                          // optional
    });

    // result.AccessToken, result.IdToken, result.RefreshToken, result.ExpiresIn, result.Scope
}
catch (CustomTokenExchangeException ex)
{
    // ex.StatusCode, ex.Error, ex.ErrorDescription describe a token-endpoint rejection;
    // a validation failure carries a descriptive message instead.
}
```

### Delegation / impersonation

Pass an actor token pair to act on behalf of another party (RFC 8693 delegation). When delegation is in play,
the `act` claim from the returned ID token is decoded and exposed on `result.Act` (the outermost `Sub` is the
current actor; nested `Act` values are prior actors, informational only). Auth0 suppresses the refresh token in
delegation flows.

```csharp
var result = await HttpContext.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
{
    SubjectToken = externalToken,
    SubjectTokenType = "urn:acme:legacy-token",
    ActorToken = actorToken,
    ActorTokenType = "urn:acme:actor-token"
});

var currentActor = result.Act?.Sub;
```

> **Note:** `subject_token_type` (and `actor_token_type`) must be custom URIs. The reserved `urn:ietf:` and
> `urn:auth0:` namespaces are rejected client-side.

## Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Log in to an organization

Log in to an organization by specifying the `Organization` when calling `AddAuth0WebAppAuthentication`:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Organization = Configuration["Auth0:Organization"];
});
```

Apart from being able to configure the organization globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply the organization when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithOrganization("YOUR_ORGANIZATION_ID_OR_NAME")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the Organization when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Organization.

### Organization claim validation

If you don't provide an `organization` parameter at login, the SDK can't validate the `org_id` (or `org_name`) claim you get back in the ID token. In that case, you should validate the `org_id` (or `org_name`) claim yourself (e.g. by checking it against a list of valid organization ID's (or names) or comparing it with the application's URL).

```
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.OpenIdConnectEvents = new OpenIdConnectEvents
    {
        OnTokenValidated = (context) =>
        {
            var organizationClaimValue = context.SecurityToken.Claims.SingleOrDefault(claim => claim.Type == "org_id")?.Value;
            var expectedOrganizationIds = new List<string> {"123", "456"};
            if (!string.IsNullOrEmpty(organizationClaimValue) && !expectedOrganizationIds.Contains(organizationClaimValue))
            {
                context.Fail("Unexpected org_id claim detected.");
            }

            return Task.CompletedTask;
        }
    };
}).
```

For more information, please read [Work with Tokens and Organizations](https://auth0.com/docs/organizations/using-tokens) on Auth0 Docs.

### Accept user invitations
Accept a user invitation through the SDK by creating a route within your application that can handle the user invitation URL, and log the user in by passing the `organization` and `invitation` parameters from this URL.

```csharp
public class InvitationController : Controller {

    public async Task Accept(string organization, string invitation)
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithOrganization(organization)
            .WithInvitation(invitation)
            .Build();
            
        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }
}
```

## Extra Parameters

Auth0's `/authorize` and `/v2/logout` endpoint support additional querystring parameters that aren't first-class citizens in this SDK. If you need to support any of those parameters, you can configure the SDK to do so.

### Extra parameters when logging in

In order to send extra parameters to Auth0's `/authorize` endpoint upon logging in, set `LoginParameters` when calling `AddAuth0WebAppAuthentication`.

An example is the `screen_hint` parameter, which can be used to show the signup page instead of the login page when redirecting users to Auth0:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.LoginParameters = new Dictionary<string, string>() { { "screen_hint", "signup" } };
});
```

Apart from being able to configure these globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply extra parameters when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithParameter("screen_hint", "signup")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying any extra parameter when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured parameter.

### Extra parameters when logging out
The same as with the login request, you can send parameters to the `logout` endpoint by calling `WithParameter` on the `LogoutAuthenticationPropertiesBuilder`.

```csharp
var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
    .WithParameter("federated")
    .Build();

await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
```
> :information_source: The example above uses a parameter without an actual value, for more information see https://auth0.com/docs/logout/log-users-out-of-idps.

## Roles

Before you can add [Role Based Access Control](https://auth0.com/docs/manage-users/access-control/rbac), you will need to ensure the required roles are created and assigned to the corresponding user(s). Follow the guidance explained in [assign-roles-to-users](https://auth0.com/docs/users/assign-roles-to-users) to ensure your user gets assigned the admin role.

Once the role is created and assigned to the required user(s), you will need to create an [action](https://auth0.com/docs/customize/actions) that adds the role(s) to the ID token so that it is available to your backend. To do so, go to the [Auth0 dashboard](https://manage.auth0.com/) and create a custom action. Then, use the following code for your action:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const assignedRoles = (event.authorization || {}).roles;

  api.idToken.setCustomClaim('http://schemas.microsoft.com/ws/2008/06/identity/claims/role', assignedRoles);
}
```

> :information_source: As this SDK uses the OpenId Connect middleware, it expects roles to exist in the `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` claim.

### Integrate roles in your ASP.NET application
You can use the [Role based authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles) mechanism to make sure that only the users with specific roles can access certain actions. Add the `[Authorize(Roles = "...")]` attribute to your controller action.

```csharp
[Authorize(Roles = "admin")]
public IActionResult Admin()
{
    return View();
}
```

## Multiple Custom Domain (MCD) Support

Multiple Custom Domains (MCD) lets you resolve the Auth0 domain per request while keeping a single SDK instance. This is useful when one application serves multiple custom domains (for example, `brand-1.my-app.com` and `brand-2.my-app.com`), each mapped to a different `Auth0` custom domain.

`MCD` is enabled by providing a `DomainResolver` function instead of a static domain string, enabling you to dynamically define the `Auth0` custom domain at run-time.

Resolver mode is intended for the custom domains of a single `Auth0` tenant. It is not a supported way to connect multiple `Auth0` tenants to one application.

### Dynamic Domain Resolver

Provide a resolver function to select the domain at runtime. The resolver should return the `Auth0 Custom Domain` (for example, `brand-1.custom-domain.com`). Returning `null` or an empty value throws `InvalidOperationException`.

### Configure with a DomainResolver

Call `WithCustomDomains()` and provide a `DomainResolver` to resolve the domain dynamically based on the incoming request. The domain can be derived from a subdomain, request header, query parameter, or any other request attribute:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
})
.WithCustomDomains(options =>
{
    // Example: resolve from a custom header
    options.DomainResolver = httpContext =>
    {
        var tenant = httpContext.Request.Headers["X-Tenant-Domain"].FirstOrDefault();
        return Task.FromResult(tenant ?? "default-tenant.auth0.com");
    };
});
```

### Resolve domain from subdomain

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
})
.WithCustomDomains(options =>
{
    // e.g., "acme.myapp.com" -> "acme.auth0.com"
    options.DomainResolver = httpContext =>
    {
        var host = httpContext.Request.Host.Host;
        var subdomain = host.Split('.')[0];
        return Task.FromResult($"{subdomain}.auth0.com");
    };
});
```

### Redirect URI requirements

When using MCD, the `redirectUri` must be an **absolute URL**. In MCD deployments, you will typically resolve the redirect URI per request so each domain uses the correct callback URL:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    // Resolve redirect URI based on the incoming request's host
    .WithRedirectUri($"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/callback")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

You must validate the host and scheme safely for your deployment to prevent open redirect attacks.

### Legacy sessions and migration

When moving from a static domain setup to a `DomainResolver`, existing sessions can continue to work if the resolver returns the same Auth0 custom domain that was used for those legacy sessions.

If the resolver returns a different domain, the SDK treats the session as missing and requires the user to sign in again. This is intentional to keep sessions isolated per domain.

### Security requirements

When configuring the `DomainResolver`, you are responsible for ensuring that all resolved domains are trusted. Mis-configuring the domain resolver is a critical security risk that can lead to authentication bypass on the relying party (RP) or expose the application to Server-Side Request Forgery (SSRF).

**Single tenant limitation:**
The `DomainResolver` is intended solely for multiple custom domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

**Secure proxy requirement:**
When using MCD, your application must be deployed behind a secure edge or reverse proxy (e.g., Cloudflare, Nginx, or AWS ALB). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in malicious redirects, where users are sent to unauthorized or fraudulent endpoints during the login and logout flows.

### Configuration Manager Cache

You can control how OpenID Connect configuration managers are cached per domain with `ConfigurationManagerCache`.

By default, the SDK uses an in-memory cache with:
- `maxSize: 100` entries
- No expiration (entries remain until evicted by size pressure)

The cache is keyed by the OIDC metadata endpoint URL (e.g., `https://brand-1.custom-domain.com/.well-known/openid-configuration`). Each distinct domain resolved by `DomainResolver` occupies one cache entry.

Most applications can keep the defaults, but you may want to adjust them in the following cases:
- Increase `maxSize` if one process may verify tokens for more than 100 distinct domains during its lifetime.
- Decrease `maxSize` if memory usage matters more than avoiding repeated OIDC discovery setup.
- Set `slidingExpiration` if you want entries that haven't been accessed within a given duration to be evicted automatically.
- Use `NullConfigurationManagerCache` to disable caching entirely (not recommended for production).

Rule of thumb: set `maxSize` to cover the number of distinct domains a single process is expected to serve, with some headroom.

#### MemoryConfigurationManagerCache (Default)

```csharp
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };

    options.ConfigurationManagerCache = new MemoryConfigurationManagerCache(
        maxSize: 100,                             // Maximum number of domains to cache
        slidingExpiration: TimeSpan.FromHours(1)  // Optional: evict entries not accessed within 1 hour
    );
});
```

#### NullConfigurationManagerCache

Disables caching entirely — a new configuration manager is created on every request (not recommended for production):

```csharp
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };
    options.ConfigurationManagerCache = new NullConfigurationManagerCache();
});
```

#### Custom Cache Implementation

Implement `IConfigurationManagerCache` for custom caching strategies (e.g., a distributed cache):

```csharp
public class MyCustomConfigurationManagerCache : IConfigurationManagerCache
{
    public IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory)
    {
        // Return a cached instance or call factory(metadataAddress) to create one
    }

    public void Clear() { /* Evict all entries */ }
    public void Dispose() { /* Clean up resources */ }
}

// Usage
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };
    options.ConfigurationManagerCache = new MyCustomConfigurationManagerCache();
});
```

## Backchannel Logout

Backchannel logout can be configured by calling `WithBackchannelLogout()` when calling `AddAuth0WebAppAuthentication`.

```csharp
services
    .AddAuth0WebAppAuthentication(PlaygroundConstants.AuthenticationScheme, options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    }).WithBackchannelLogout();

```

Additionally, you will also need to call `UseBackchannelLogout();` on the ApplicationBuilder:

```csharp
app.UseBackchannelLogout();
```

When using a custom scheme, make sure to use the same scheme name consistently throughout your authentication flow (login, logout, and backchannel logout configuration).

As logout tokens need to be stored, you will also need to provide something for our SDK to store the tokens in.

```csharp
services.AddTransient<ILogoutTokenHandler, CustomLogoutTokenHandler>();
```

The implementation of `CustomLogoutTokenHandler` will heaviliy depend on your situation, but here's a blueprint you can use:

```csharp
 public class CustomLogoutTokenHandler : ILogoutTokenHandler
{
    public CustomLogoutTokenHandler()
    {
    }

    public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
    {
        // When a token is received, you need to store it for the duration of `expiration`, using `issuer` and `sid` as the identifiers.
    }

    public Task<bool> IsLoggedOutAsync(string issuer, string sid)
    {
        // Return a boolean based on whether or not you find a logout token using the `issuer` and `sid`.
    }
}
```

### Distributed caching
If you want to connect the backchannel logout to a [distributed cache](https://learn.microsoft.com/en-us/aspnet/core/performance/caching/distributed), such as redis, to store the logout tokens, you can use:

```csharp
public class CustomDistributedLogoutTokenHandler : ILogoutTokenHandler
{
    private readonly IDistributedCache _cache;

    public CustomDistributedLogoutTokenHandler(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
    {
        await _cache.SetAsync($"{issuer}|{sid}", Encoding.ASCII.GetBytes(logoutToken), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiration
        });
    }

    public async Task<bool> IsLoggedOutAsync(string issuer, string sid)
    {
        var token = await _cache.GetAsync($"{issuer}|{sid}");
        return token != null;
    }
}
```

## Blazor Server

The `Auth0-AspNetCore-Authentication` SDK works with Blazor Server in an almost identical way as how it's integrated in ASP.NET Core MVC.

### Register the SDK
Registering the SDK is identical as with ASP.NET Core MVC, where you should call `builder.Services.AddAuth0WebAppAuthentication` inside `Program.cs`, and ensure the authentication middleware (`UseAuthentication()` and `UseAuthorization()`) is registered.

```csharp
builder.Services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.ClientId = builder.Configuration["Auth0:ClientId"];
    options.Scope = "openid profile email";
});

// ...

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

### Add login and logout
Adding login and logout capabilities is different in the sense that you should create a `PageModel` implementation for both to allow the user to be redirected to Auth0.

```csharp
public class LoginModel : PageModel
{
    public async Task OnGet(string redirectUri)
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithRedirectUri(redirectUri)
            .Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }
}

[Authorize]
public class LogoutModel : PageModel
{
    public async Task OnGet()
    {
        var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                .WithRedirectUri("/")
                .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
```
