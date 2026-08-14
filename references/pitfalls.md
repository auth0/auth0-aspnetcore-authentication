# Common Pitfalls

- **Builder ordering is load-bearing.** `WithCustomDomains` must be called **before** `WithMtls`, and `WithMtls` **before** `WithAccessToken`. Both custom-domains and mTLS register an `IPostConfigureOptions<OpenIdConnectOptions>` that touches the `ConfigurationManager`; post-configures run in registration order, and the wrong order silently routes the code exchange / PAR to the non-mTLS endpoints. The builder throws `InvalidOperationException` when the order is violated — preserve those guards.

- **`GetAccessTokenAsync` is not concurrency-safe per session.** Concurrent calls for the same session each operate on their own session snapshot (last write wins) and, with refresh-token rotation, can trigger reuse detection and invalidate the whole session. Callers serialize per session or plug in an `ITicketStore` via `WithSessionStore`. Don't "optimize" it into parallel refreshes.

- **mTLS credential exclusivity.** Under mTLS the client certificate is the sole credential; `WithMtls` rejects a co-configured `ClientSecret`, `ClientAssertionSecurityKey`, or `Backchannel`. `ValidateOptions` short-circuits when `UseMtls` is set — keep both paths consistent when changing credential validation.

- **Multi-targeting.** The library targets `net6.0`, `net7.0`, `net8.0`, and `net10.0`, each pinned to the matching `Microsoft.AspNetCore.Authentication.OpenIdConnect` major. A change that compiles on one TFM may fail on another — build the affected framework (see [commands.md](commands.md)) rather than assuming.

- **Telemetry header.** Requests to Auth0 carry an `Auth0-Client` header set once in `Auth0OpenIdConnectPostConfigureOptions.cs` on the backchannel `HttpClient`. A new hand-rolled `HttpClient` for an Auth0 call would drop it — reuse the configured backchannel instead.
