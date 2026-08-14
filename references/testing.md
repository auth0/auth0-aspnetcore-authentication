# Testing

- **Framework:** xUnit 2.9.3
- **Assertions:** FluentAssertions 7.2.2 (`result.Should().Be(...)`, `.Should().BeNull()`, `.Should().Throw<T>()`)
- **Mocking:** Moq 4.20.72
- **Host/integration:** `Microsoft.AspNetCore.Mvc.Testing` (in-process `TestServer`)
- **Coverage:** coverlet.collector (`dotnet test --collect:"XPlat Code Coverage"`)
- **Location:** `tests/Auth0.AspNetCore.Authentication.IntegrationTests/`

## Nature of the suite

Despite the `IntegrationTests` project name, the suite runs **in-process against a mocked OIDC provider** — no live Auth0 tenant, no real credentials. `appsettings.json` uses placeholder values (`"123"`), and OIDC responses are stubbed. `dotnet test` is safe to run at any time.

Key test infrastructure:

- `Builders/OidcMockBuilder.cs` — stubs the OIDC discovery/token endpoints.
- `Infrastructure/TestServerBuilder.cs` — spins up the ASP.NET Core test host.
- `Infrastructure/TestAuthHandler.cs`, `CapturingLoggerProvider.cs`, `TestConfiguration.cs` — auth + logging + config helpers.
- Embedded `wellknownconfig*.json` / `jwks*.json` resources back the mocked discovery documents (including mTLS and PAR variants).

## Conventions

- One test class per unit under test, named `<Type>Tests` in namespace `Auth0.AspNetCore.Authentication.IntegrationTests[.<Area>]`.
- Methods use `[Fact]` / `[Theory]` with descriptive PascalCase names describing behavior + condition, e.g. `Returns_Null_When_Aliases_Absent`.
- Prefer small `private static` helpers to build fixtures (see `MtlsEndpointAliasesTests.WithAliases`).
- Assert with FluentAssertions, not raw `Assert.*`.

The library exposes internals to the test project via `[InternalsVisibleTo("Auth0.AspNetCore.Authentication.IntegrationTests")]`, so tests can exercise internal helpers directly.
