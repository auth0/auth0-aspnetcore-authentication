# Auth0 SDK for ASP.NET Core MVC (Beta)
[![Build status](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_apis/build/status/Auth0.AspNetCore.MVC)](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_build/latest?definitionId=8)

This library supports .NET 5 and is a wrapper around `Microsoft.AspNetCore.Authentication.OpenIdConnect` to make integrating Auth0 in your ASP.NET Core 5 application using [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post) as seamlessly as possible.

> :information_source: This SDK is designed to support the most common use-cases. If you have more complex needs, you can still integrate Auth0 using `Microsoft.AspNetCore.Authentication.OpenIdConnect` directly.

## Table of Contents

- [Documentation](#documentation)
- [Installation](#installation)
- [Getting Started](#getting-started)
  - [Login and Logout](#login-and-logout)
  - [Scopes](#scopes)
  - [Calling an API](#calling-an-api)
  - [Organization](#organization)
  - [Extra Parameters](#extra-parameters)
  - [Roles](#roles)
- [Contributing](#contributing)
- [Support + Feedback](#support--feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Documentation

- API Reference
- Quickstart Guide

## Installation

The SDK is available on Nuget and can be installed through the UI or using the Package Manager Console:

```
Install-Package Auth0.AspNetCore.Mvc -IncludePrerelease
```

As the SDK is still in beta, you need to tell Nuget to also include prereleases, either by using the `-IncludePrerelease` flag when using the Package Manager Console, or by checking the `Include prerelease` checkbox when installing the SDK through the Package Manager UI.

## Getting Started

Integrate the SDK in your ASP.NET Core application by calling `AddAuth0Mvc` in your `Startup.ConfigureServices` method:

```csharp
services.AddAuth0Mvc(options =>
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
    await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = returnUrl });
}

[Authorize]
public async Task Logout()
{
    // Indicate here where Auth0 should redirect the user after a logout.
    // Note that the resulting absolute Uri must be added in the
    // **Allowed Logout URLs** settings for the client.
    await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = Url.Action("Index", "Home") });
    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
}
```

> :warning: Make sure you have enabled​ authentication and authorization in your `Startup.Configure` method:
>
> ```csharp
> ...
> app.UseAuthentication();
> app.UseAuthorization();
> ...
> ```

### Scopes

By default, this SDK requests the `openid profile email` scopes, if needed you can configure the SDK to request a different set of scopes.

```csharp
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Scope = "openid profile email scope1 scope2";
});
```

Apart from being able to configure the used scopes globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply scopes when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithScope("openid profile email scope1 scope2")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: specifying the scopes when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured scopes. Ensure to also include `openid profile email` if you need them as well.

### Calling an API

If you want to call an API from your ASP.NET MVC application, you need to obtain an Access Token issued for the API you want to call. 
As the SDK is configured to use OAuth's [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post), no access token will be returned by default. In order to do so, we should be using the [Authorization Code Grant](https://auth0.com/docs/flows/authorization-code-flow), which requires the use of a `ClientSecret`.
Next, To obtain the token to access an external API, set the `audience` to the API Identifier when calling `AddAuth0Mvc`. You can get the API Identifier from the API Settings for the API you want to use.

```csharp
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.ClientSecret = Configuration["Auth0:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.Audience = Configuration["Auth0:Audience"];
});
```

Apart from being able to configure the audience globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply the audience when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithRedirectUri("/") // "/" is the default value used for RedirectUri, so this can be omitted.
    .WithAudience("YOUR_AUDIENCE")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: specifying the Audience when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Audience.

#### Retrieving the Access Token

As the SDK uses the OpenId Connect middleware, the ID Token is decoded and the corresponding claims are added to the `ClaimsIdentity`, making them available by using `User.Claims`.

The access token can be retrieved by calling `HttpContext.GetTokenAsync("access_token")`.

```csharp
[Authorize]
public async Task<IActionResult> Profile()
{
    var accessToken = await HttpContext.GetTokenAsync("access_token");

    return View(new UserProfileViewModel()
    {
        Name = User.Identity.Name,
        EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
        ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
    });
}
```
### Organization

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Using Organizations, you can:

- Represent teams, business customers, partner companies, or any logical grouping of users that should have different ways of accessing your applications, as organizations.

- Manage their membership in a variety of ways, including user invitation.

- Configure branded, federated login flows for each organization.

- Implement role-based access control, such that users can have different roles when authenticating in the context of different organizations.

- Build administration capabilities into your products, using Organizations APIs, so that those businesses can manage their own organizations.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

#### Log in to an organization

Log in to an organization by specifying the `Organization` when calling `AddAuth0Mvc`:

```csharp
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Organization = Configuration["Auth0:Organization"];
});
```

Apart from being able to configure the organization globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply the organization when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithOrganization("YOUR_ORGANIZATION")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: specifying the Organization when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Organization.

#### Accept user invitations
Accept a user invitation through the SDK by creating a route within your application that can handle the user invitation URL, and log the user in by passing the `organization` and `invitation` parameters from this URL.

```csharp
public class InvitationController : Controller {

    public async Task Accept(string organization, string invitation)
    {
        var authenticationProperties = new AuthenticationPropertiesBuilder()
            .WithOrganization(organization)
            .WithInvitation(invitation)
            .Build();
            
        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }
}

```

### Extra Parameters

Auth0's `/authorize` endpoint supports additional querystring parameters that aren't first-class citizens in this SDK. If you need to support any of those parameters, you can configure the `ExtraParameters` when calling `AddAuth0Mvc`.

An example is the `screen_hint` parameter, which can be used to show the signup page instead of the login page when redirecting users to Auth0:

```csharp
services.AddAuth0Mvc(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.ExtraParameters = new Dictionary<string, string>() { { "screen_hint", "signup" } };
});
```

Apart from being able to configure these globally, the SDK's `AuthenticationPropertiesBuilder` can be used to supply extra parameters when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new AuthenticationPropertiesBuilder()
    .WithExtraParameter("screen_hint", "signup")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: specifying any extra parameter when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured parameter.

### Roles

Before you can add Role Based Access Control, you will need to ensure the required roles are created and assigned to the corresponding user(s). Follow the guidance explained in [assign-roles-to-users](https://auth0.com/docs/users/assign-roles-to-users) to ensure your user gets assigned the admin role.

Once the role is created and assigned to the required user(s), you will need to create a [rule](https://auth0.com/docs/rules/current) that adds the role(s) to the ID Token so that it is available to your backend. To do so, go to the [new rule page](https://manage.auth0.com/#/rules/new) and create an empty rule. Then, use the following code for your rule:

```javascript
function (user, context, callback) {
  const assignedRoles = (context.authorization || {}).roles;
  const idTokenClaims = context.idToken || {};

  idTokenClaims['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'] = assignedRoles;

  context.idToken = idTokenClaims;

  callback(null, user, context);
}
```

> :information_source: As this SDK uses the OpenId Connect middleware, it expects roles to exist in the `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` claim.

## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines](https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md)
- [This repo's contribution guide](CONTRIBUTING.md)

## Support + Feedback

For support or to provide feedback, please [raise an issue on our issue tracker](https://github.com/auth0/auth0-aspnetcore-mvc/issues).

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

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.