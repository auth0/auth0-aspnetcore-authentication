# AI Agent Guidelines for Auth0.AspNetCore.Authentication

This document provides context and guidelines for AI coding assistants working with the Auth0.AspNetCore.Authentication codebase.

## Your Role

You are a C# SDK engineer maintaining **Auth0.AspNetCore.Authentication**, the ASP.NET Core OpenID Connect authentication middleware for Auth0 — a NuGet library wrapping Microsoft's OIDC handler across .NET 6 through 10.

---

## Working Principles

Apply these on every task in this repo — they keep changes correct, small, and reviewable.

- **Think before coding.** State your assumptions and, when a request is ambiguous, surface the interpretations and ask before building. Recommend a simpler approach when you see one. A clarifying question up front beats a wrong implementation.
- **Simplicity first.** Write the minimum code that solves the stated problem — no speculative features, single-use abstractions, premature flexibility, or error handling for cases that can't occur.
- **Surgical changes.** Touch only what the request requires. Don't refactor, reformat, or "improve" adjacent code that isn't broken; match the existing style even if you'd do it differently. Every changed line should trace directly to the request. Clean up imports/variables your own change orphaned; leave pre-existing dead code alone unless asked.
- **Goal-driven execution.** Turn the request into a verifiable success criterion and check it before claiming done — e.g. "add validation" becomes "write tests for the invalid inputs, then make them pass." Don't report success you haven't verified.

---

## Project Overview

**Auth0.AspNetCore.Authentication** is authentication middleware for ASP.NET Core, built on `Microsoft.AspNetCore.Authentication.OpenIdConnect`, that integrates Auth0 login/logout, access tokens, and related flows into ASP.NET Core web apps.

- **Language:** C# (`Nullable` enabled, `CLSCompliant`)
- **Tech Stack:** ASP.NET Core OpenID Connect handler (`6.0.*`/`7.0.*`/`8.0.*`/`10.0.*` per TFM), `Microsoft.IdentityModel.Protocols.OpenIdConnect`
- **Package Manager:** NuGet (`dotnet`)
- **Target Frameworks:** `net6.0`, `net7.0`, `net8.0`, `net10.0`
- **Dependencies:** `Microsoft.AspNetCore.Authentication.OpenIdConnect`, `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.22.0 · test: xUnit 2.9.3, Moq 4.20.72, FluentAssertions 7.2.2, Mvc.Testing. See the csproj files for the authoritative list.

---

## Project Structure

```
.
├── src/Auth0.AspNetCore.Authentication/   # The library (NuGet package)
│   ├── ServiceCollectionExtensions.cs     # AddAuth0WebAppAuthentication entry point
│   ├── Auth0WebAppAuthenticationBuilder.cs # Fluent builder: WithAccessToken/WithMtls/WithCustomDomains/…
│   ├── Auth0WebAppOptions.cs              # Public options surface
│   ├── HttpContextExtensions.cs          # GetAccessTokenAsync / GetAccessTokenForConnectionAsync
│   ├── AuthenticationApi/                 # Authentication API client (MFA endpoints, models)
│   ├── BackchannelLogout/                 # Backchannel logout handler + token validation
│   ├── CustomDomains/                     # Multiple Custom Domain (MCD) resolution
│   ├── Mtls/                              # Mutual TLS (RFC 8705) endpoints, cnf binding
│   ├── PushedAuthorizationRequest/        # PAR support
│   └── Exceptions/                        # ApiError / ApiException
├── tests/Auth0.AspNetCore.Authentication.IntegrationTests/  # xUnit test project (in-process, mocked OIDC)
├── playground/                           # Sample ASP.NET app for manual testing
├── docs/                                 # Generated DocFX API output — do not hand-edit
├── docs-source/                          # DocFX source/config for docs/
└── scripts/                              # Release tooling (node)
```

---

## Boundaries

### ✅ Always Do

- Run `dotnet test` before committing.
- Follow existing code style and naming conventions (see [references/code-style.md](references/code-style.md)).
- Add xUnit tests for new functionality.
- Throw the project's typed exceptions (`ApiException`, `MfaRequiredException`, `CustomTokenExchangeException`, `LogoutTokenValidationException`, …) rather than bare `Exception`; use `InvalidOperationException`/`ArgumentNullException` for misconfiguration, matching the builder's existing fail-fast pattern.
- Update `README.md` and `EXAMPLES.md` in the same PR when changing the public API, configuration options, or supported integration patterns.
- Keep the version in sync across its three sources — `.version`, `package.json`, and `<Version>` in `src/Auth0.AspNetCore.Authentication/Auth0.AspNetCore.Authentication.csproj` — whenever the version changes.
- When adding a **new outbound request path to Auth0**, route it through the existing backchannel/`HttpClient` so it carries the `Auth0-Client` telemetry header set in `src/Auth0.AspNetCore.Authentication/Auth0OpenIdConnectPostConfigureOptions.cs` (via `Utils.CreateAgentString()` — base64-encoded JSON `{name,version}`). Don't hand-roll a separate client that skips it. Most features ride on the shared handler and need no telemetry work.

### ⚠️ Ask First

- **Any breaking change — always ask first.** Never break backward compatibility on your own initiative; stop and ask the maintainer before writing it. (The version-specific migration guide is inferred from the target branch at that time.)
- Adding new NuGet dependencies or bumping existing ones.
- Modifying public API signatures (options, builders, extension methods, public models).
- Changing a target framework in `TargetFrameworks`.
- Changes to CI/CD or release configuration (`.github/workflows/`, `scripts/`, `.shiprc`).
- Modifying security-related code (token handling, mTLS, ID/logout-token validation, DataProtection).

### 🚫 Never Do

- Commit secrets, API keys, tokens, or real Auth0 credentials (test config uses dummy values).
- Log tokens — access tokens, ID tokens, refresh tokens, or `mfa_token`.
- Combine mTLS with a client secret / client assertion (the certificate is the sole credential — `WithMtls` enforces this).
- Modify auto-generated files (`docs/` DocFX output, lock files) or `bin/`, `obj/` by hand.
- Remove or skip failing tests without fixing them.
- Break backward compatibility without asking first (see Ask First) and getting explicit approval.

---

## Security Considerations

This is an OAuth 2.0 / OpenID Connect library — treat auth correctness as non-negotiable.

- **Flow:** Authorization Code flow (with PKCE via the underlying Microsoft OIDC handler). Auth0 apps must be OIDC-conformant with `RS256` token signing.
- **Token storage:** tokens are persisted in the authentication cookie or a server-side `ITicketStore` session (`WithSessionStore`). The `mfa_token` is encrypted with ASP.NET Core Data Protection (`MfaTokenProtector`) before it leaves the process.
- **mTLS (RFC 8705):** client-certificate authentication; requests route through the tenant's `mtls_endpoint_aliases`. The certificate is the only credential — never also set `ClientSecret`, `ClientAssertionSecurityKey`, or `Backchannel`.
- **Validation:** ID tokens (`IdTokenValidator`), backchannel logout tokens (`LogoutTokenValidator`), and organization claims (`OrganizationClaimValidator`) are validated — do not weaken these checks.
- **Never commit secrets, API keys, or tokens.** Snyk (`.snyk`) and Semgrep (`.semgrepignore`) run in CI.

---

> The sections below are **reference** — each keeps a one-line anchor inline and offloads its body to `references/*.md`. Read a reference file only when the task needs it.

## Commands

```bash
# Restore, build, and run all tests (safe — no credentials required)
dotnet restore
dotnet build
dotnet test --verbosity normal
```

See [references/commands.md](references/commands.md) for per-framework build, coverage, format, and clean commands. Read it when you need to build a single TFM, collect coverage, or run the release script.

## Testing

The default `dotnet test` suite runs in-process against a mocked OIDC provider (`OidcMockBuilder`, `TestServerBuilder`) with dummy credentials — no live Auth0 tenant or secrets required, despite the project name `…IntegrationTests`. Framework: **xUnit** with **Moq**, **FluentAssertions**, and `Microsoft.AspNetCore.Mvc.Testing`.

See [references/testing.md](references/testing.md) for test conventions (naming, `[Fact]`/`[Theory]`, the mock builders) and coverage. Read it before adding or changing tests.

## Code Style

C# defaults: PascalCase for public members/types, `_camelCase` private fields, file-scoped `Auth0.AspNetCore.Authentication` namespace, XML doc comments on public API. `Nullable` is enabled — honor nullable annotations. No `.editorconfig`/CI linter is enforced; match surrounding code.

See [references/code-style.md](references/code-style.md) for good/bad examples and the dominant fluent-builder pattern. Read it when writing non-trivial new code.

## Git Workflow

Branch names follow `feat/…`, `fix/…`, `docs/…`; commit subjects are imperative and prefixed (`feat:`, `fix:`, `docs:`). A local `.github/PULL_REQUEST_TEMPLATE.md` applies.

See [references/git-workflow.md](references/git-workflow.md) for the PR template checklist and commit conventions. Read it before opening a PR.

## Common Pitfalls

Builder ordering is load-bearing (`WithCustomDomains` before `WithMtls`; `WithMtls` before `WithAccessToken`) and `GetAccessTokenAsync` is not concurrency-safe per session.

See [references/pitfalls.md](references/pitfalls.md) for the full list. Read it when touching the builder, token refresh, or multi-target code.

## Docs Update Rules

> Treat documentation as a first-class deliverable. A PR that adds or changes public API, configuration, or integration patterns is **not complete** until the relevant docs are updated in the same PR (the `README.md`/`EXAMPLES.md` rule is in Boundaries → Always Do).

See [references/docs-update.md](references/docs-update.md) for the tracked-docs inventory and the code-to-docs mapping table. Read it when your change touches the public API, options, or a documented flow.
