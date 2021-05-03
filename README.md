# Auth0 SDK for ASP.NET Core MVC (Beta)
[![Build status](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_apis/build/status/Auth0.AspNetCore.MVC)](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_build/latest?definitionId=8)

This library supports .NET 5 and is a wrapper around `Microsoft.AspNetCore.Authentication.OpenIdConnect` to make integrating Auth0 in your ASP.NET Core 5 application using [Authorization Code Grant Flow with PKCE](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce) as seamlessly as possible.

> :information_source: This SDK is designed to support the most common use-cases. In the event that you have more complex needs, you can still integrate Auth0 using `Microsoft.AspNetCore.Authentication.OpenIdConnect` directly.

## Table of Contents

- [Documentation](#documentation)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Support + Feedback](#support--feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Documentation

- [Documentation](https://auth0.com/docs/libraries/auth0-spa-js)
- [API reference](https://auth0.github.io/auth0-spa-js/)
- Migrate from `Microsoft.AspNetCore.Authentication.OpenIdConnect` to the Auth0 ASP.NET MVC SDK

## Installation

The SDK is available on Nuget and can be installed through the UI or using the Package Manager Console:

```
Install-Package Auth0.AspNetCore.Mvc -IncludePrerelease
```

## Getting Started

Integrate the SDK in your ASP.NET Core application by calling `AddAuth0Mvc` in your `Startup.ConfigureService` method:

```
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.ClientSecret = Configuration["Auth0:ClientSecret"];
});
```

Triggering login or logout is done using ASP.NET's `HttpContext`:

```
public async Task Login(string returnUrl = "/")
{
    await HttpContext.ChallengeAsync(Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = "/" });
}

[Authorize]
public async Task Logout()
{
    // Indicate here where Auth0 should redirect the user after a logout.
    // Note that the resulting absolute Uri must be whitelisted in the
    // **Allowed Logout URLs** settings for the client.
    await HttpContext.SignOutAsync(Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = Url.Action("Index", "Home") });
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
```

### Scopes

By default, this SDK requests the `openid profile email` scopes, if needed you can configure the SDK to request a different set of scopes.

```
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.ClientSecret = Configuration["Auth0:ClientSecret"];
    options.Scope = "openid profile email scope1 scope2";
});
```

Apart from being able to configure the used scopes globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply scopes when triggering login through `HttpContext.ChallengeAsync`:

```
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithRedirectUri("/")
    .WithScope("openid profile email scope1 scope2")
    .Build();

await HttpContext.ChallengeAsync(Constants.AuthenticationScheme, authenticationProperties);
```

> When specifying the used scopes, the default values will be ignored. Ensure to also include `openid profile email` if you need them as well.

### Audience

If you want to call an API from your ASP.NET MVC application, you need to obtain an Access Token issued for the API you want to call. To obtain the token, set the `audience` to the API Identifier when calling `AddAuth0Mvc`. You can get the API Identifier from the API Settings for the API you want to use.

```
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.ClientSecret = Configuration["Auth0:ClientSecret"];
    options.Audience = Configuration["Auth0:Audience"];
});
```

Apart from being able to configure the audience globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply the audience when triggering login through `HttpContext.ChallengeAsync`:

```
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithRedirectUri("/")
    .WithAudience("YOUR_AUDIENCE")
    .Build();

await HttpContext.ChallengeAsync(Constants.AuthenticationScheme, authenticationProperties);
```

### Organization

### Extra Parameters

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/auth0-spa-js/blob/main/CONTRIBUTING.md)

## Support + Feedback

```
For support or to provide feedback, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-aspnetcore-mvc/issues).
```

## Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## What is Auth0

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

This project is licensed under the MIT license. See the [LICENSE](https://github.com/auth0/auth0-aspnetcore-mvc/blob/main/LICENSE) file for more info.