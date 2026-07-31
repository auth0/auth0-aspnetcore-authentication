# Change Log

## [1.10.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.10.0) (2026-07-31)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.9.0...1.10.0)

**Added**
- **Upstream IdP session expiry (IPSIE SL1) enforcement** [\#272](https://github.com/auth0/auth0-aspnetcore-authentication/pull/272) ([tanya732](https://github.com/tanya732)) - when Auth0 brokers an upstream identity provider that enforces its own session lifetime, that ceiling now caps the session in the application too, so a user is not kept signed in past the point the upstream IdP considers their session over. Enforcement is automatic and requires no code opt-in; it activates only when the connection emits a `session_expiry` claim (Unix seconds) on the ID token (connection option `id_token_session_expiry_supported`).

**Security**
- **Bump dependencies** [\#274](https://github.com/auth0/auth0-aspnetcore-authentication/pull/274) ([dependabot[bot]](https://github.com/apps/dependabot)) - consolidates several Dependabot bumps (supersedes #267, #271): `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.19.2 → 8.22.0.
- **Dependency updates** [\#266](https://github.com/auth0/auth0-aspnetcore-authentication/pull/266) ([kailash-b](https://github.com/kailash-b)) - bundles a set of routine Dependabot updates keeping both the NuGet package references and GitHub Actions workflow versions current.
  - NuGet packages: `Microsoft.AspNetCore.Mvc.Testing` 10.0.9 → 10.0.10, `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.19.1 → 8.19.2, `Microsoft.NET.Test.Sdk` 18.6.0 → 18.8.1, `System.Text.Encodings.Web` 10.0.9 → 10.0.10.

## [1.9.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.9.0) (2026-07-08)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.8.0...1.9.0)

**Added**

- **Token Vault support** [\#255](https://github.com/auth0/auth0-aspnetcore-authentication/pull/255) ([kailash-b](https://github.com/kailash-b)) - web apps can now obtain a third-party API access token for a federated connection (e.g. Google, GitHub, Slack) on behalf of the logged-in user by exchanging the session's refresh token, without running a separate provider OAuth flow.
  - New `HttpContext.GetAccessTokenForConnectionAsync(AccessTokenForConnectionRequest, string? scheme = null)` extension serves an unexpired connection token from the session cache when possible, and otherwise exchanges the refresh token and persists the result.
  - `AccessTokenForConnectionRequest` carries `Connection` (required), an optional `LoginHint` (the provider-side IdP user ID), and `ForceRefresh` to bypass the cache.
  - Returns `null` rather than throwing when no refresh token is present (fires `OnMissingRefreshToken`) or the exchange is rejected (fires `OnAccessTokenRefreshFailed`).
- **Custom Token Exchange support** [\#258](https://github.com/auth0/auth0-aspnetcore-authentication/pull/258) ([kailash-b](https://github.com/kailash-b)) - applications can exchange an existing external/custom security token for Auth0 tokens without a browser redirect ([RFC 8693](https://auth0.com/docs/authenticate/custom-token-exchange)), enabling delegation/impersonation and agent-identity scenarios. Requires a Custom Token Exchange Profile and a validation Action configured in the tenant.
  - New `HttpContext.CustomTokenExchangeAsync(CustomTokenExchangeRequest)` extension performs the exchange. `CustomTokenExchangeRequest` takes `SubjectToken` and `SubjectTokenType` (required), plus optional `Audience`, `Scope`, an `ActorToken`/`ActorTokenType` delegation pair, and `Organization`.
  - `CustomTokenExchangeResult` returns the exchanged tokens (`AccessToken`, `IdToken`, `RefreshToken`, `ExpiresIn`, `Scope`) and the decoded `act` (actor) claim for delegation flows.
  - **Stateless by design** - the exchange returns tokens but has no session side-effects: it does not sign the user in or write any cookie, leaving the caller to decide what to persist.
  - Client-side validation runs before any network call (`subject_token` must be non-empty and un-prefixed; `subject_token_type` must be a valid 10–100 character URI, rejecting the reserved `urn:ietf:` and `urn:auth0:` namespaces; an actor token requires its matching type). Failures surface as `CustomTokenExchangeException`, which carries `StatusCode`, `Error`, and `ErrorDescription` but never token-bearing bytes.
- **Claims refresh and `OnTokensRefreshed` event on token refresh** [\#254](https://github.com/auth0/auth0-aspnetcore-authentication/pull/254) ([kailash-b](https://github.com/kailash-b)) - previously, refreshing an expired access token persisted the new tokens but left the `ClaimsPrincipal` at its login-time snapshot for the life of the refresh token. Two opt-in additions let applications react to a successful primary refresh (fixes [\#174](https://github.com/auth0/auth0-aspnetcore-authentication/issues/174)).
  - New `Auth0WebAppWithAccessTokenOptions.RebuildPrincipalOnRefresh` (default `false`) rebuilds the `ClaimsPrincipal` from the refreshed `id_token` so `User.Claims` and `User.Identity.Name` reflect current user information.
  - New `Auth0WebAppWithAccessTokenOptions.RefreshClaimsValidationType` controls how the refreshed `id_token` is validated before its claims replace the principal (only consulted when `RebuildPrincipalOnRefresh` is `true`): `Full` (default) validates signature against the cached JWKS plus issuer/audience and business-rule checks, while `SkipSignature` trusts the back-channel TLS exchange and runs only the business-rule checks.
  - New `Auth0WebAppWithAccessTokenEvents.OnTokensRefreshed` event fires after every successful primary refresh; the `AccessTokenRefreshedContext` carries the refreshed `AccessToken`, `IdToken`, `RefreshToken` (null when not rotated), and `ExpiresAt`. It fires independently of `RebuildPrincipalOnRefresh`, and after the principal is rebuilt when both are used.
  - **Graceful degradation** - if the refresh succeeds but rebuilding the principal fails (signature failure, malformed token, or business-rule failure), the SDK keeps the refreshed tokens, retains the existing (stale) principal, logs a warning, and still fires `OnTokensRefreshed`.
  - Both additions apply only to the primary (login-time) refresh path; tokens fetched for additional audiences via MRRT do not rebuild the principal or fire `OnTokensRefreshed`.

## [1.8.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.8.0) (2026-06-29)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.7.1...1.8.0)

**Added**

- **Multi-Resource Refresh Token (MRRT) support** [\#249](https://github.com/auth0/auth0-aspnetcore-authentication/pull/249), [\#251](https://github.com/auth0/auth0-aspnetcore-authentication/pull/251) ([kailash-b](https://github.com/kailash-b)) - applications can now obtain access tokens for additional audiences and scopes on demand by exchanging the session's refresh token, without forcing the user through another interactive login.
  - New `HttpContext.GetAccessTokenAsync(AccessTokenRequest)` extension returns an access token for a requested audience and/or scope, served from the session cache when possible and otherwise via a refresh-token exchange.
  - Configure default scopes per audience with `Auth0WebAppWithAccessTokenOptions.ScopeByAudience`.
  - The new `OnAccessTokenRefreshFailed` event surfaces refresh failures, letting callers distinguish terminal failures (warranting re-login) from transient ones.
  - **MFA challenge handling** - when a refresh requires MFA, a new `MfaRequiredException` surfaces the challenge, and `IAuthenticationApiClient` (registered via `WithAuthenticationApiClient()`) lets the application complete OTP, OOB, or recovery-code grants and manage authenticators.
- **Configurable access-token expiration leeway** [\#247](https://github.com/auth0/auth0-aspnetcore-authentication/pull/247) ([kailash-b](https://github.com/kailash-b)) - new `Auth0WebAppWithAccessTokenOptions.AccessTokenExpirationLeeway` (`TimeSpan`, default 60s) controls how far ahead of expiry the SDK proactively refreshes the access token. Previously hard-coded to 60 seconds; the default preserves prior behavior. Applies to both primary and additional (MRRT) cached tokens, and only takes effect when `UseRefreshTokens` is enabled.
- **Configurable server-side session store** [\#246](https://github.com/auth0/auth0-aspnetcore-authentication/pull/246) ([kailash-b](https://github.com/kailash-b)) - new `WithSessionStore` method on `Auth0WebAppAuthenticationBuilder` stores the authentication session server-side (via `ITicketStore`) instead of in the cookie. It attaches the store to the SDK's own resolved cookie scheme, so it works even with a custom `CookieAuthenticationScheme`. Two overloads are provided: `WithSessionStore<TStore>()` (resolved from DI) and `WithSessionStore(ITicketStore instance)`. Opt-in and additive; the default stateless cookie session is unchanged.

**Fixed**

- **Remove duplicate trailing slash from `client_assertion` audience** [\#236](https://github.com/auth0/auth0-aspnetcore-authentication/pull/236) ([samjetski](https://github.com/samjetski)) - fixes a regression introduced in 1.7.0 (#206) where the Private Key JWT client assertion `aud` claim was built as `https://{tenant}//` (double slash), causing Auth0's `/oauth/token` endpoint to reject the assertion with `401 invalid_client` and leaving affected apps (any using `ClientAssertionSecurityKey`) in a callback loop.
- **Wire `OnValidatePrincipal` to the configured cookie scheme** [\#248](https://github.com/auth0/auth0-aspnetcore-authentication/pull/248) ([kailash-b](https://github.com/kailash-b)) - fixes a scheme mismatch where the access-token refresh hook was registered against the default `"Cookies"` scheme rather than the configured `CookieAuthenticationScheme`.

**Security**

- **Bump dependencies** [\#250](https://github.com/auth0/auth0-aspnetcore-authentication/pull/250) ([kailash-b](https://github.com/kailash-b)) - consolidates several Dependabot bumps (supersedes #240, #242, #243, #244): `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.18.0 → 8.19.1, `Microsoft.AspNetCore.Mvc.Testing` 10.0.8 → 10.0.9, `Microsoft.AspNetCore.Mvc.ViewFeatures` 2.3.10 → 2.3.11, `System.Text.Encodings.Web` 10.0.8 → 10.0.9.
- **Pin GitHub Actions to commit SHAs** [\#241](https://github.com/auth0/auth0-aspnetcore-authentication/pull/241) ([jcchavezs](https://github.com/jcchavezs)) - pins all third-party actions in the workflow files to commit SHAs for improved supply-chain security and reproducibility.

## [1.7.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.7.1) (2026-06-08)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.7.0...1.7.1)

This is a maintenance release that updates runtime and test dependencies to their latest patch versions.

**Security**
- chore: Upgrade dependencies — bundles [\#231](https://github.com/auth0/auth0-aspnetcore-authentication/pull/231), [\#232](https://github.com/auth0/auth0-aspnetcore-authentication/pull/232), [\#233](https://github.com/auth0/auth0-aspnetcore-authentication/pull/233), [\#234](https://github.com/auth0/auth0-aspnetcore-authentication/pull/234), [\#235](https://github.com/auth0/auth0-aspnetcore-authentication/pull/235) (`System.Text.Encodings.Web` 10.0.8, `Microsoft.AspNetCore.Mvc.Testing` 10.0.8, `Microsoft.AspNetCore.Mvc.ViewFeatures` 2.3.10, `Microsoft.NET.Test.Sdk` 18.6.0, `coverlet.collector` 10.0.1) [\#237](https://github.com/auth0/auth0-aspnetcore-authentication/pull/237) ([kailash-b](https://github.com/kailash-b))
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.17.0 to 8.18.0 [\#230](https://github.com/auth0/auth0-aspnetcore-authentication/pull/230) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.NET.Test.Sdk from 18.4.0 to 18.5.1 [\#229](https://github.com/auth0/auth0-aspnetcore-authentication/pull/229) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump System.Text.Encodings.Web from 10.0.6 to 10.0.7 [\#228](https://github.com/auth0/auth0-aspnetcore-authentication/pull/228) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.AspNetCore.Mvc.Testing from 10.0.6 to 10.0.7 [\#227](https://github.com/auth0/auth0-aspnetcore-authentication/pull/227) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump System.Text.Encodings.Web from 10.0.5 to 10.0.6 [\#225](https://github.com/auth0/auth0-aspnetcore-authentication/pull/225) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.AspNetCore.Mvc.Testing from 10.0.5 to 10.0.6 [\#224](https://github.com/auth0/auth0-aspnetcore-authentication/pull/224) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.NET.Test.Sdk from 18.3.0 to 18.4.0 [\#222](https://github.com/auth0/auth0-aspnetcore-authentication/pull/222) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.16.0 to 8.17.0 [\#221](https://github.com/auth0/auth0-aspnetcore-authentication/pull/221) ([dependabot[bot]](https://github.com/apps/dependabot))

## [1.7.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.7.0) (2026-04-09)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.6.1...1.7.0)

**Added**
- Adds support for multiple custom domains [\#206](https://github.com/auth0/auth0-aspnetcore-authentication/pull/206) ([kailash-b](https://github.com/kailash-b))

**Security**
- chore: Dependency updates [\#220](https://github.com/auth0/auth0-aspnetcore-authentication/pull/220) ([kailash-b](https://github.com/kailash-b))
- chore(deps): Bump System.Text.Encodings.Web from 10.0.2 to 10.0.3 [\#209](https://github.com/auth0/auth0-aspnetcore-authentication/pull/209) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.AspNetCore.Mvc.Testing from 10.0.2 to 10.0.3 [\#208](https://github.com/auth0/auth0-aspnetcore-authentication/pull/208) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps)(deps): Bump actions/checkout from 5 to 6 [\#192](https://github.com/auth0/auth0-aspnetcore-authentication/pull/192) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump FluentAssertions from 7.2.0 to 7.2.1 [\#207](https://github.com/auth0/auth0-aspnetcore-authentication/pull/207) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.15.0 to 8.16.0 [\#211](https://github.com/auth0/auth0-aspnetcore-authentication/pull/211) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.AspNetCore.Mvc.ViewFeatures from 2.3.0 to 2.3.9 [\#203](https://github.com/auth0/auth0-aspnetcore-authentication/pull/203) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.AspNetCore.Mvc.Testing from 10.0.1 to 10.0.2 [\#204](https://github.com/auth0/auth0-aspnetcore-authentication/pull/204) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump System.Text.Encodings.Web from 10.0.1 to 10.0.2 [\#205](https://github.com/auth0/auth0-aspnetcore-authentication/pull/205) ([dependabot[bot]](https://github.com/apps/dependabot))

## [1.6.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.6.1) (2025-12-22)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.6.0...1.6.1)

**Security**
- chore(deps): Bump System.Text.Encodings.Web from 10.0.0 to 10.0.1 [\#200](https://github.com/auth0/auth0-aspnetcore-authentication/pull/200) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.14.0 to 8.15.0 [\#190](https://github.com/auth0/auth0-aspnetcore-authentication/pull/190) ([dependabot[bot]](https://github.com/apps/dependabot))

## [1.6.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.6.0) (2025-12-04)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.5.1...1.6.0)

**Added**
- Adds support for net10.0 [\#195](https://github.com/auth0/auth0-aspnetcore-authentication/pull/195) ([kailash-b](https://github.com/kailash-b))

**Fixed**
- Remove refresh_token from cookie instead of setting to NULL [\#193](https://github.com/auth0/auth0-aspnetcore-authentication/pull/193) ([kailash-b](https://github.com/kailash-b))

## [1.5.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.5.1) (2025-11-07)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.5.0...1.5.1)

**Fixed**
- Fix issue with using custom scheme with BackchannelLogout [\#185](https://github.com/auth0/auth0-aspnetcore-authentication/pull/185) ([kailash-b](https://github.com/kailash-b))

**Security**
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.13.1 to 8.14.0 [\#172](https://github.com/auth0/auth0-aspnetcore-authentication/pull/172) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(deps): Bump Microsoft.IdentityModel.Protocols.OpenIdConnect from 8.12.1 to 8.13.1 [\#168](https://github.com/auth0/auth0-aspnetcore-authentication/pull/168) ([dependabot[bot]](https://github.com/apps/dependabot))

## [1.5.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.5.0) (2025-07-21)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.4.1...1.5.0)

**Security**
- Upgrade dependency versions and fix failing tests [\#151](https://github.com/auth0/auth0-aspnetcore-authentication/pull/151) ([kailash-b](https://github.com/kailash-b))

## [1.4.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.4.1) (2024-01-25)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.4.0...1.4.1)

**Added**
- Adds SignInScheme, SignOutScheme, ForwardSignIn, and ForwardSignOut [\#136](https://github.com/auth0/auth0-aspnetcore-authentication/pull/136) ([CasperWSchmidt](https://github.com/CasperWSchmidt))

**Changed**
- Explicitly add .NET8 support [\#130](https://github.com/auth0/auth0-aspnetcore-authentication/pull/130) ([frederikprijck](https://github.com/frederikprijck))

## [1.4.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.4.0) (2023-12-05)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.3.1...1.4.0)

**Added**
- Add support for backchannel logout [\#125](https://github.com/auth0/auth0-aspnetcore-authentication/pull/125) ([frederikprijck](https://github.com/frederikprijck))
- Add support for Pushed Authorization Request [\#124](https://github.com/auth0/auth0-aspnetcore-authentication/pull/124) ([frederikprijck](https://github.com/frederikprijck))

**Changed**
- Support OpenIdConnectOptions.AccessDeniedPath [\#123](https://github.com/auth0/auth0-aspnetcore-authentication/pull/123) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- Allow using ClientAssertion when setting ResponseType [\#119](https://github.com/auth0/auth0-aspnetcore-authentication/pull/119) ([frederikprijck](https://github.com/frederikprijck))

## [1.3.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.3.1) (2023-07-18)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.3.0...1.3.1)

**Changed**
- Do not lowercase org_name claim [\#110](https://github.com/auth0/auth0-aspnetcore-authentication/pull/110) ([frederikprijck](https://github.com/frederikprijck))

## [1.3.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.3.0) (2023-07-13)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.2.0...1.3.0)

**Added**
- Support Organization Name [\#105](https://github.com/auth0/auth0-aspnetcore-authentication/pull/105) ([frederikprijck](https://github.com/frederikprijck))

## [1.2.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.2.0) (2023-03-10)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.1.0...1.2.0)

**Added**
- Ensure CookieName is configurable [\#98](https://github.com/auth0/auth0-aspnetcore-authentication/pull/98) ([nquandt](https://github.com/nquandt))

**Changed**
- Avoid creating HttpClient when using refresh tokens [\#95](https://github.com/auth0/auth0-aspnetcore-authentication/pull/95) ([frederikprijck](https://github.com/frederikprijck))
- Use IOptionsMonitor instead of IOptionsSnapshot [\#96](https://github.com/auth0/auth0-aspnetcore-authentication/pull/96) ([frederikprijck](https://github.com/frederikprijck))

## [1.1.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.1.0) (2023-01-16)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.4...1.1.0)

**Added**
- Add support for Client Assertion [\#93](https://github.com/auth0/auth0-aspnetcore-authentication/pull/93) ([frederikprijck](https://github.com/frederikprijck))

**Changed**
- Drop .NET Core 3.1; Add .NET 7 [\#91](https://github.com/auth0/auth0-aspnetcore-authentication/pull/91) ([frederikprijck](https://github.com/frederikprijck))
- Drop support for .NET5 [\#90](https://github.com/auth0/auth0-aspnetcore-authentication/pull/90) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- Update Microsoft.IdentityModel.Protocols.OpenIdConnect dependency to avoid memory leak [\#89](https://github.com/auth0/auth0-aspnetcore-authentication/pull/89) ([frederikprijck](https://github.com/frederikprijck))

## [1.0.4](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.4) (2022-09-19)
[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.3...1.0.4)

**Fixed**
- [SDK-3619] Do not update refresh token when rotation is disabled [\#81](https://github.com/auth0/auth0-aspnetcore-authentication/pull/81) ([frederikprijck](https://github.com/frederikprijck))

[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.2...1.0.3)

**Fixed**
- Pin version of Microsoft.IdentityModel.Protocols.OpenIdConnect [\#72](https://github.com/auth0/auth0-aspnetcore-authentication/pull/72)

## [1.0.2](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.2) (2022-05-04)

[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.1...1.0.2)

**Fixed**
- Fix auto refresh issue with Refresh Tokens [\#67](https://github.com/auth0/auth0-aspnetcore-authentication/pull/67)

**Changed**
- Add dependencies for .NET6.0 [\#68](https://github.com/auth0/auth0-aspnetcore-authentication/pull/68)

## [1.0.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.1) (2022-02-14)

[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.0...1.0.1)

**Changed**
- Support specifying a custom scheme [\#59](https://github.com/auth0/auth0-aspnetcore-authentication/pull/59)

## [1.0.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.0-beta.1) (2021-09-16)

[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.0-beta.1...1.0.0)

**Install**

```
Install-Package Auth0.AspNetCore.Authentication
```

**Usage**

Integrate the SDK in your ASP.NET Core application by calling `AddAuth0WebAppAuthentication` in your `Startup.ConfigureService` method:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
});
```

**Features**
- Cookie & OpenIdConnect Authentication (using [Implicit Flow with Form Post](https://auth0.com/docs/authorization/flows/implicit-flow-with-form-post) as the default)
- Automatic Logout URL configuration
- Retrieving Access Tokens to call an API (using [Authorization Code Flow with PKCE](https://auth0.com/docs/authorization/flows/authorization-code-flow-with-proof-key-for-code-exchange-pkce))
- Refreshing the Access Token when expired using Refresh Tokens
- Access to all native OpenIdConnect events

**Migration Guide**

When your application is currently using `Microsoft.AspNetCore.Authentication.OpenIdConnect`, migrating to our ASP.NET Core SDK is rather straightforward. Read our [Migration Guide](MIGRATION.md) for more information.

## [1.0.0-beta.1](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.0-beta.1) (2021-09-16)

[Full Changelog](https://github.com/auth0/auth0-aspnetcore-authentication/compare/1.0.0-beta.0...1.0.0-beta.1)

**Changed**
- Rename SDK to Auth0.AspNetCore.Authentication [#49](https://github.com/auth0/auth0-aspnetcore-authentication/pull/49) ([frederikprijck](https://github.com/frederikprijck))

## [1.0.0-beta.0](https://github.com/auth0/auth0-aspnetcore-authentication/tree/1.0.0-beta.0) (2021-05-27)

**Install**

```
Install-Package Auth0.AspNetCore.Authentication -IncludePrerelease
```

**Usage**

Integrate the SDK in your ASP.NET Core application by calling `AddAuth0WebAppAuthentication` in your `Startup.ConfigureService` method:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
});
```

**Added**

- Implement Basic Cookie & OpenIdConnect Authentication [#7](https://github.com/auth0/auth0-aspnetcore-authentication/pull/7) ([frederikprijck](https://github.com/frederikprijck))
- Support configuring the Scopes [#8](https://github.com/auth0/auth0-aspnetcore-authentication/pull/8) ([frederikprijck](https://github.com/frederikprijck))
- Support configuring the callback path [#9](https://github.com/auth0/auth0-aspnetcore-authentication/pull/9) ([frederikprijck](https://github.com/frederikprijck))
- Add builder for AuthenticationProperties [#11](https://github.com/auth0/auth0-aspnetcore-authentication/pull/11) ([frederikprijck](https://github.com/frederikprijck))
- Configure Auth0 logout URL [#10](https://github.com/auth0/auth0-aspnetcore-authentication/pull/10) ([frederikprijck](https://github.com/frederikprijck))
- Support custom parameters [#12](https://github.com/auth0/auth0-aspnetcore-authentication/pull/12) ([frederikprijck](https://github.com/frederikprijck))
- Configure User Agent [#15](https://github.com/auth0/auth0-aspnetcore-authentication/pull/15) ([frederikprijck](https://github.com/frederikprijck))
- Support Audience [#13](https://github.com/auth0/auth0-aspnetcore-authentication/pull/13) ([frederikprijck](https://github.com/frederikprijck))
- Save tokens to be able to retrieve them [#17](https://github.com/auth0/auth0-aspnetcore-authentication/pull/17) ([frederikprijck](https://github.com/frederikprijck)
- Use Implicit flow instead of Code flow [#21](https://github.com/auth0/auth0-aspnetcore-authentication/pull/21) ([frederikprijck](https://github.com/frederikprijck))
- Re-add support for Code Flow to be able to retrieve Access Tokens [#22](https://github.com/auth0/auth0-aspnetcore-authentication/pull/22) ([frederikprijck](https://github.com/frederikprijck)
- Support Refresh Tokens [#31](https://github.com/auth0/auth0-aspnetcore-authentication/pull/31) ([frederikprijck](https://github.com/frederikprijck)
- Proxy all OpenId Connect Events [#34](https://github.com/auth0/auth0-aspnetcore-authentication/pull/34) ([frederikprijck](https://github.com/frederikprijck)
- Rework to move Access Token to `WithAccessToken()` [#35](https://github.com/auth0/auth0-aspnetcore-authentication/pull/35) ([frederikprijck](https://github.com/frederikprijck)
- Rework Extra Parameters and support logout endpoint [#37](https://github.com/auth0/auth0-aspnetcore-authentication/pull/37) ([frederikprijck](https://github.com/frederikprijck)
