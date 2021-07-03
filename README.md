# Auth0 SDK for ASP.NET Core MVC (Beta)
[![Build status](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_apis/build/status/Auth0.AspNetCore.MVC)](https://dev.azure.com/Auth0SDK/Auth0.AspNetCore.Mvc/_build/latest?definitionId=8)

This library supports .NET Core 3.1 and .NET 5 and is a wrapper around `Microsoft.AspNetCore.Authentication.OpenIdConnect` to make integrating Auth0 in your ASP.NET Core  application using [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post) as seamlessly as possible.

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

### Auth0 Configuration

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

### Basic Setup

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

### Scopes

By default, this SDK requests the `openid profile` scopes, if needed you can configure the SDK to request a different set of scopes.
As `openid` is a [required scope](https://auth0.com/docs/scopes/openid-connect-scopes), the SDk will ensure the `openid` scope is always added, even when explicitly omitted when setting the scope.

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Scope = "openid profile scope1 scope2";
});
```

Apart from being able to configure the used scopes globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply scopes when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithScope("openid profile scope1 scope2")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the scopes when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured scopes.

### Calling an API

If you want to call an API from your ASP.NET MVC application, you need to obtain an Access Token issued for the API you want to call. 
As the SDK is configured to use OAuth's [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post), no access token will be returned by default. In order to do so, we should be using the [Authorization Code Grant](https://auth0.com/docs/flows/authorization-code-flow), which requires the use of a `ClientSecret`.
Next, To obtain the token to access an external API, call `WithAccessToken` and set the `audience` to the API Identifier. You can get the API Identifier from the API Settings for the API you want to use.

```csharp
services
    .AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    })
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
    });
```

Apart from being able to configure the audience globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply the audience when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithRedirectUri("/") // "/" is the default value used for RedirectUri, so this can be omitted.
    .WithAudience("YOUR_AUDIENCE")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the Audience when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Audience.

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

#### Refresh Tokens

In the case where the application needs to use an Access Token to access an API, there may be a situation where the Access Token expires before the application's session does. In order to ensure you have a valid Access Token at all times, you can configure the SDK to use Refresh Tokens:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuth0WebAppAuthentication(options =>
        {
            options.Domain = Configuration["Auth0:Domain"];
            options.ClientId = Configuration["Auth0:ClientId"];
            options.ClientSecret = Configuration["Auth0:ClientSecret"];
        })
        .WithAccessToken(options =>
        {
            options.Audience = Configuration["Auth0:Audience"];
            options.UseRefreshTokens = true;
        });
}
```

##### Detecting the absense of a Refresh Token

In the event where the API, defined in your Auth0 dashboard, isn't configured to [allow offline access](https://auth0.com/docs/get-started/dashboard/api-settings), or the user was already logged in before the use of Refresh Tokens was enabled (e.g. a user logs in a few minutes before the use of refresh tokens is deployed), it might be useful to detect the absense of a Refresh Token in order to react accordingly (e.g. log the user out locally and force them to re-login).

```
services
    .AddAuth0WebAppAuthentication(options => {})
    .WithAccessToken(options =>
    {
        options.Audience = Configuration["Auth0:Audience"];
        options.UseRefreshTokens = true;
        options.Events = new Auth0WebAppWithAccessTokenEvents
        {
            OnMissingRefreshToken = async (context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                var authenticationProperties = new LogoutAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            }
        };
    });
```

The above snippet checks whether the SDK is configured to use Refresh Tokens, if there is an existing Id Token (meaning the user is authenticaed) as well as the absense of a Refresh Token. If each of these criteria are met, it logs the user out (from the application's side, not from Auth0's side) and initialized a new login flow.

> :information_source: In order for Auth0 to redirect back to the application's login URL, ensure to add the configured redirect URL to the application's `Allowed Logout URLs` in Auth0's dashboard.

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

Log in to an organization by specifying the `Organization` when calling `AddAuth0WebAppAuthentication`:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.Organization = Configuration["Auth0:Organization"];
});
```

Apart from being able to configure the organization globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply the organization when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithOrganization("YOUR_ORGANIZATION")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the Organization when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Organization.

#### Organization Claim Validation

If you don't provide an `organization` parameter at login, the SDK can't validate the `org_id` claim you get back in the ID Token. In that case, you should validate the `org_id` claim yourself (e.g. by checking it against a list of valid organization ID's or comparing it with the application's URL).

```
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.OpenIdConnectEvents = new OpenIdConnectEvents
    {
        OnTokenValidated = (context) =>
        {
            var organizationClaimValue = context.SecurityToken.Claims.SingleOrDefault(claim => claim.Type == "org_id")?.Value;
            var expectedOrganizationIds = new List<string> {"123", "456"};
            if (!string.IsNullOrEmpty(organizationClaimValue) && !expectedOrganizationIds.Contains(organizationClaimValue))
            {
                context.Fail("Unexpected org_id claim detected.");
            }

            return Task.CompletedTask;
        }
    };
}).
```

For more information, please read [Work with Tokens and Organizations](https://auth0.com/docs/organizations/using-tokens) on Auth0 Docs.

#### Accept user invitations
Accept a user invitation through the SDK by creating a route within your application that can handle the user invitation URL, and log the user in by passing the `organization` and `invitation` parameters from this URL.

```csharp
public class InvitationController : Controller {

    public async Task Accept(string organization, string invitation)
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithOrganization(organization)
            .WithInvitation(invitation)
            .Build();
            
        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }
}
```

### Extra Parameters

Auth0's `/authorize` and `/v2/logout` endpoint support additional querystring parameters that aren't first-class citizens in this SDK. If you need to support any of those parameters, you can configure the SDK to do so.

#### Extra parameters when logging in

In order to send extra parameters to Auth0's `/authorize` endpoint upon logging in, set `LoginParameters` when calling `AddAuth0WebAppAuthentication`.

An example is the `screen_hint` parameter, which can be used to show the signup page instead of the login page when redirecting users to Auth0:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
    options.LoginParameters = new Dictionary<string, string>() { { "screen_hint", "signup" } };
});
```

Apart from being able to configure these globally, the SDK's `LoginAuthenticationPropertiesBuilder` can be used to supply extra parameters when triggering login through `HttpContext.ChallengeAsync`:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    .WithParameter("screen_hint", "signup")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying any extra parameter when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured parameter.

#### Extra parameters when logging out
The same as with the login request, you can send parameters to the `logout` endpoint by calling `WithParameter` on the `LogoutAuthenticationPropertiesBuilder`.

```csharp
var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
    .WithParameter("federated")
    .Build();

await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
```
> :information_source: The example above uses a parameter without an actual value, for more information see https://auth0.com/docs/logout/log-users-out-of-idps.

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

#### Integrate roles in your ASP.NET application
You can use the [Role based authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles) mechanism to make sure that only the users with specific roles can access certain actions. Add the `[Authorize(Roles = "...")]` attribute to your controller action.

```csharp
[Authorize(Roles = "admin")]
public IActionResult Admin()
{
    return View();
}
```

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
