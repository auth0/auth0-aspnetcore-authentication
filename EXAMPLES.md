# Examples using auth0-aspnetcore-authentication

- [Login and Logout](#login-and-logout)
- [Scopes](#scopes)
- [Calling an API](#calling-an-api)
- [Organizations](#organizations)
- [Extra parameters](#extra-parameters)
- [Roles](#roles)
- [Blazor Server](#blazor-server)

## Login and Logout
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

## Scopes

By default, this SDK requests the `openid profile` scopes, if needed you can configure the SDK to request a different set of scopes.
As `openid` is a [required scope](https://auth0.com/docs/scopes/openid-connect-scopes), the SDK will ensure the `openid` scope is always added, even when explicitly omitted when setting the scope.

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

## Calling an API

If you want to call an API from your ASP.NET MVC application, you need to obtain an access token issued for the API you want to call. 
As the SDK is configured to use OAuth's [Implicit Grant with Form Post](https://auth0.com/docs/flows/implicit-flow-with-form-post), no access token will be returned by default. In order to do so, we should be using the [Authorization Code Grant](https://auth0.com/docs/flows/authorization-code-flow), which requires the use of a `ClientSecret`.
Next, to obtain the token to access an external API, call `WithAccessToken` and set the `audience` to the API Identifier. You can get the API Identifier from the API Settings for the API you want to use.

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

### Retrieving the access token

As the SDK uses the OpenId Connect middleware, the ID token is decoded and the corresponding claims are added to the `ClaimsIdentity`, making them available by using `User.Claims`.

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

### Refresh tokens

In the case where the application needs to use an access token to access an API, there may be a situation where the access token expires before the application's session does. In order to ensure you have a valid access token at all times, you can configure the SDK to use refresh tokens:

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

#### Detecting the absense of a refresh token

In the event where the API, defined in your Auth0 dashboard, isn't configured to [allow offline access](https://auth0.com/docs/get-started/dashboard/api-settings), or the user was already logged in before the use of refresh tokens was enabled (e.g. a user logs in a few minutes before the use of refresh tokens is deployed), it might be useful to detect the absense of a refresh token in order to react accordingly (e.g. log the user out locally and force them to re-login).

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

The above snippet checks whether the SDK is configured to use refresh tokens, if there is an existing ID token (meaning the user is authenticated) as well as the absence of a refresh token. If each of these criteria are met, it logs the user out from the application and initializes a new login flow.

> :information_source: In order for Auth0 to redirect back to the application's login URL, ensure to add the configured redirect URL to the application's `Allowed Logout URLs` in Auth0's dashboard.

## Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.

Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Log in to an organization

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
    .WithOrganization("YOUR_ORGANIZATION_ID_OR_NAME")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

> :information_source: Specifying the Organization when calling `HttpContext.ChallengeAsync` will take precedence over any globally configured Organization.

### Organization claim validation

If you don't provide an `organization` parameter at login, the SDK can't validate the `org_id` (or `org_name`) claim you get back in the ID token. In that case, you should validate the `org_id` (or `org_name`) claim yourself (e.g. by checking it against a list of valid organization ID's (or names) or comparing it with the application's URL).

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

### Accept user invitations
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

## Extra Parameters

Auth0's `/authorize` and `/v2/logout` endpoint support additional querystring parameters that aren't first-class citizens in this SDK. If you need to support any of those parameters, you can configure the SDK to do so.

### Extra parameters when logging in

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

### Extra parameters when logging out
The same as with the login request, you can send parameters to the `logout` endpoint by calling `WithParameter` on the `LogoutAuthenticationPropertiesBuilder`.

```csharp
var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
    .WithParameter("federated")
    .Build();

await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
```
> :information_source: The example above uses a parameter without an actual value, for more information see https://auth0.com/docs/logout/log-users-out-of-idps.

## Roles

Before you can add [Role Based Access Control](https://auth0.com/docs/manage-users/access-control/rbac), you will need to ensure the required roles are created and assigned to the corresponding user(s). Follow the guidance explained in [assign-roles-to-users](https://auth0.com/docs/users/assign-roles-to-users) to ensure your user gets assigned the admin role.

Once the role is created and assigned to the required user(s), you will need to create an [action](https://auth0.com/docs/customize/actions) that adds the role(s) to the ID token so that it is available to your backend. To do so, go to the [Auth0 dashboard](https://manage.auth0.com/) and create a custom action. Then, use the following code for your action:

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const assignedRoles = (event.authorization || {}).roles;

  api.idToken.setCustomClaim('http://schemas.microsoft.com/ws/2008/06/identity/claims/role', assignedRoles);
}
```

> :information_source: As this SDK uses the OpenId Connect middleware, it expects roles to exist in the `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` claim.

### Integrate roles in your ASP.NET application
You can use the [Role based authorization](https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles) mechanism to make sure that only the users with specific roles can access certain actions. Add the `[Authorize(Roles = "...")]` attribute to your controller action.

```csharp
[Authorize(Roles = "admin")]
public IActionResult Admin()
{
    return View();
}
```

## Blazor Server

The `Auth0-AspNetCore-Authentication` SDK works with Blazor Server in an almost identical way as how it's integrated in ASP.NET Core MVC.

### Register the SDK
Registering the SDK is identical as with ASP.NET Core MVC, where you should call `builder.Services.AddAuth0WebAppAuthentication` inside `Program.cs`, and ensure the authentication middleware (`UseAuthentication()` and `UseAuthorization()`) is registered.

```csharp
builder.Services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"];
    options.ClientId = builder.Configuration["Auth0:ClientId"];
    options.Scope = "openid profile email";
});

// ...

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

### Add login and logout
Adding login and logout capabilities is different in the sense that you should create a `PageModel` implementation for both to allow the user to be redirected to Auth0.

```csharp
public class LoginModel : PageModel
{
    public async Task OnGet(string redirectUri)
    {
        var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
            .WithRedirectUri(redirectUri)
            .Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }
}

[Authorize]
public class LogoutModel : PageModel
{
    public async Task OnGet()
    {
        var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                .WithRedirectUri("/")
                .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
```

For more information on how to integrate this SDK in Blazor Server, have a look at our dedicated [Blazor Server example](https://github.com/auth0-samples/auth0-aspnetcore-blazor-samples/blob/main/Quickstart/Sample).