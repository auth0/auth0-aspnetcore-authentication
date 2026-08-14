# Code Style

No `.editorconfig` or CI linter is enforced; match the surrounding code. `Nullable` is enabled project-wide.

## Naming & structure

- **PascalCase** for public types, methods, properties; **`_camelCase`** for private fields; **camelCase** for locals/parameters.
- One public type per file, file named after the type.
- Namespace `Auth0.AspNetCore.Authentication` (block-scoped, as in existing files).
- XML doc comments (`/// <summary>`) on every public member — the docs site (DocFX) is generated from them.
- `using` directives at the top, framework namespaces first.

## Dominant pattern: fluent builder

The public API is a fluent builder (`Auth0WebAppAuthenticationBuilder`) whose `With*` methods configure DI and return `this`. Configuration errors fail fast with `InvalidOperationException` and a message that explains the fix.

**✅ Good** — returns the builder, validates eagerly, explains the constraint:

```csharp
public Auth0WebAppAuthenticationBuilder WithMtls(Action<Auth0MtlsOptions> configureOptions)
{
    var mtlsOptions = new Auth0MtlsOptions();
    configureOptions(mtlsOptions);

    if (mtlsOptions.HttpClient == null)
    {
        throw new InvalidOperationException(
            "WithMtls requires an HttpClient configured with the client certificate.");
    }

    _mtlsConfigured = true;
    // ...register services...
    return this;
}
```

**❌ Bad** — swallows misconfiguration, doesn't return the builder, no doc comment:

```csharp
public void WithMtls(Action<Auth0MtlsOptions> configureOptions)
{
    var o = new Auth0MtlsOptions();
    configureOptions(o);
    if (o.HttpClient != null)          // silently no-ops when null
        _options.Backchannel = o.HttpClient;
}
```

## Error handling

Throw typed exceptions (`ApiException`, `MfaRequiredException`, `CustomTokenExchangeException`, `LogoutTokenValidationException`, `IdTokenValidationException`, …) so callers can catch specifically. Use `InvalidOperationException` / `ArgumentNullException` for programmer/configuration errors.
