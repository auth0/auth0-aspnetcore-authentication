# Docs Update Rules

Treat docs as a first-class deliverable — update them in the **same PR** as the code change.

## Tracked docs

| File | What it covers | Exists |
|------|----------------|--------|
| `README.md` | Installation, quick-start (login/logout, config), feature overviews (MCD, mTLS, MRRT, Token Vault), API reference links | ✅ |
| `EXAMPLES.md` | Runnable code samples for every supported scenario (access tokens, session storage, MRRT, Token Vault, custom token exchange, session transfer, organizations, MCD, mTLS, backchannel logout) | ✅ |

> `docs/` is **generated DocFX API output** (from `docs-source/` + XML doc comments) — never hand-edit it; update the XML doc comments in source instead. `CHANGELOG.md` and `MIGRATION.md` are maintained by the release flow, not by feature PRs.

## When you change code, update these docs

This is a **library / SDK** — the public surface is exported types, options, builders, and extension methods.

| When this changes | Update these docs |
|-------------------|-------------------|
| Public API (extension methods, builder `With*` methods, public options/models, `HttpContext` extensions) | `README.md` (usage), `EXAMPLES.md` (all affected samples) |
| Configuration options (`Auth0WebAppOptions`, `Auth0MtlsOptions`, `Auth0CustomDomainsOptions`, `appsettings` schema) | `README.md` (configuration/feature section) |
| Authentication / authorization flow (login, logout, token refresh, mTLS, MFA) | `README.md` (quick-start / feature section), `EXAMPLES.md` (affected examples) |
| Install / package name / target frameworks | `README.md` (Requirements + Installation) |
| A new public method or exported type added | `EXAMPLES.md` (add a usage sample), `README.md` API reference list |
| A public method or type removed or renamed | `README.md` + `EXAMPLES.md` (remove/update references) |
| A new integration pattern supported | `EXAMPLES.md` (add integration example) |
