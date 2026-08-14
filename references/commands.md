# Commands

The exact commands used in CI (`.github/workflows/build.yml`) and local development.

```bash
# Restore dependencies
dotnet restore

# Build (all target frameworks)
dotnet build

# Build a single target framework (as CI does, per-TFM: net6.0/net7.0/net8.0/net10.0)
dotnet build --no-restore --framework net8.0 src/Auth0.AspNetCore.Authentication/Auth0.AspNetCore.Authentication.csproj

# Run all tests
dotnet test --verbosity normal

# Run a single test class
dotnet test --filter "FullyQualifiedName~MtlsEndpointAliasesTests"

# Run tests with coverage (coverlet.collector)
dotnet test --collect:"XPlat Code Coverage"

# Format (not enforced in CI; no .editorconfig — matches default C# conventions)
dotnet format

# Clean
dotnet clean
```

> CI builds each target framework separately in a matrix (`net6.0`, `net7.0`, `net8.0`, `net10.0`) but runs `dotnet test` once. Release is driven by `npm run release` (`scripts/release`) — do not run it manually; releases are cut via the release flow.
