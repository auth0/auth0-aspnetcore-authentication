![Auth0 SDK for ASP.NET Core applications](https://cdn.auth0.com/website/sdks/banners/auth0-aspnetcore-authentication-banner.png)

A library based on `Microsoft.AspNetCore.Authentication.OpenIdConnect` to make integrating Auth0 in your ASP.NET Core application as seamlessly as possible.

![Release](https://img.shields.io/github/v/release/auth0/auth0-aspnetcore-authentication)
![Downloads](https://img.shields.io/nuget/dt/auth0.aspnetcore.authentication)
[![License](https://img.shields.io/:license-MIT-blue.svg?style=flat)](https://opensource.org/licenses/MIT)
![AzureDevOps](https://img.shields.io/azure-devops/build/Auth0SDK/Auth0.AspNetCore.Authentication/8)

:books: [Documentation](#documentation) - :rocket: [Getting Started](#getting-started) - :computer: [API Reference](#api-reference) - :speech_balloon: [Feedback](#feedback)

## Documentation

- [Quickstart](https://auth0.com/docs/quickstart/webapp/aspnet-core) - our interactive guide for quickly adding login, logout and user information to an ASP.NET MVC application using Auth0.
- [Sample App](https://github.com/auth0-samples/auth0-aspnetcore-mvc-samples/tree/master/Quickstart/Sample) - a full-fledged ASP.NET MVC application integrated with Auth0.
- [Examples](https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/EXAMPLES.md) - code samples for common ASP.NET MVC authentication scenario's.
- [Docs site](https://www.auth0.com/docs) - explore our docs site and learn more about 

## Getting started
### Requirements

This library supports .NET 6 and .NET 7.

### Installation

The SDK is available on [Nuget](https://www.nuget.org/packages/Auth0.AspNetCore.Authentication) and can be installed through the UI or using the Package Manager Console:

```
Install-Package Auth0.AspNetCore.Authentication
```

### Configure Auth0

Create a **Regular Web Application** in the [Auth0 Dashboard](https://manage.auth0.com/#/applications).

> **If you're using an existing application**, verify that you have configured the following settings in your Regular Web Application:
>
> - Click on the "Settings" tab of your application's page.
> - Scroll down and click on "Advanced Settings".
> - Under "Advanced Settings", click on the "OAuth" tab.
> - Ensure that "JSON Web Token (JWT) Signature Algorithm" is set to `RS256` and that "OIDC Conformant" is enabled.

Next, configure the following URLs for your application under the "Application URIs" section of the "Settings" page:

- **Allowed Callback URLs**: `https://YOUR_APP_DOMAIN:YOUR_APP_PORT/callback`
- **Allowed Logout URLs**: `https://YOUR_APP_DOMAIN:YOUR_APP_PORT/`

Take note of the **Client ID**, **Client Secret**, and **Domain** values under the "Basic Information" section. You'll need these values to configure your ASP.NET web application.

> :information_source: You need the **Client Secret** only when you have to get an access token to [call an API](#calling-an-api).

### Configure the SDK

To make your ASP.NET web application communicate properly with Auth0, you need to add the following configuration section to your `appsettings.json` file:

```json
  "Auth0": {
    "Domain": "YOUR_AUTH0_DOMAIN",
    "ClientId": "YOUR_AUTH0_CLIENT_ID"
  }
```

Replace the placeholders with the proper values from the Auth0 Dashboard.

Make sure you have enabled authentication and authorization in your `Startup.Configure` method:

```csharp
...
app.UseAuthentication();
app.UseAuthorization();
...
```

Integrate the SDK in your ASP.NET Core application by calling `AddAuth0WebAppAuthentication` in your `Startup.ConfigureServices` method:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
});
```

### Login and Logout
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

For more code samples on how to integrate the **auth0-aspnetcore-authentication** SDK in your **ASP.NET MVC** application, have a look at our [examples](https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/EXAMPLES.md).

> This SDK also works with Blazor Server, for more info see [the Blazor Server section in our examples](https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/EXAMPLES.md#blazor-server).

## API reference
Explore public API's available in auth0-aspnetcore-authentication.

- [Auth0WebAppOptions](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.Auth0WebAppOptions.html)
- [Auth0WebAppWithAccessTokenOptions](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.Auth0WebAppWithAccessTokenOptions.html)
- [LoginAuthenticationPropertiesBuilder](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.LoginAuthenticationPropertiesBuilder.html)
- [LogoutAuthenticationPropertiesBuilder](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.LogoutAuthenticationPropertiesBuilder.html)
- [Auth0WebAppAuthenticationBuilder](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.Auth0WebAppAuthenticationBuilder.html)
- [Auth0WebAppWithAccessTokenAuthenticationBuilder](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.Auth0WebAppWithAccessTokenAuthenticationBuilder.html)

## Feedback
### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/CONTRIBUTING.md)

### Raise an issue

To provide feedback or report a bug, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-aspnetcore-authentication/issues).

### Vulnerability Reporting

Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/responsible-disclosure-policy) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.auth0.com/website/sdks/logos/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="https://cdn.auth0.com/website/sdks/logos/auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the MIT license. See the <a href="https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/LICENSE"> LICENSE</a> file for more info.</p>
