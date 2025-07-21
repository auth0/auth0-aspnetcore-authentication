# Change Log

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
