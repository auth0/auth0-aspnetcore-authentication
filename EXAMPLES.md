# Examples using auth0-aspnetcore-authentication

- [Login and Logout](#login-and-logout)
- [Scopes](#scopes)
- [Calling an API](#calling-an-api)
  - [Configuring the refresh leeway](#configuring-the-refresh-leeway)
- [Organizations](#organizations)
- [Extra parameters](#extra-parameters)
- [Roles](#roles)
- [Multiple Custom Domain (MCD) Support](#multiple-custom-domain-mcd-support)
- [Backchannel Logout](#backchannel-logout)
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

#### Configuring the refresh leeway

When refresh tokens are enabled, the SDK refreshes the access token slightly *before* it actually expires, so a request in flight isn't left holding a token that lapses mid-call. This window defaults to **60 seconds**. You can tune it with `AccessTokenExpirationLeeway`:

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
        options.UseRefreshTokens = true;
        // Refresh the access token up to 2 minutes before it expires.
        options.AccessTokenExpirationLeeway = TimeSpan.FromSeconds(120);
    });
```

A larger leeway refreshes more eagerly (fewer near-expiry tokens, more refresh calls); a smaller leeway refreshes later. The leeway only takes effect when `UseRefreshTokens` is enabled.

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

## Multiple Custom Domain (MCD) Support

Multiple Custom Domains (MCD) lets you resolve the Auth0 domain per request while keeping a single SDK instance. This is useful when one application serves multiple custom domains (for example, `brand-1.my-app.com` and `brand-2.my-app.com`), each mapped to a different `Auth0` custom domain.

`MCD` is enabled by providing a `DomainResolver` function instead of a static domain string, enabling you to dynamically define the `Auth0` custom domain at run-time.

Resolver mode is intended for the custom domains of a single `Auth0` tenant. It is not a supported way to connect multiple `Auth0` tenants to one application.

### Dynamic Domain Resolver

Provide a resolver function to select the domain at runtime. The resolver should return the `Auth0 Custom Domain` (for example, `brand-1.custom-domain.com`). Returning `null` or an empty value throws `InvalidOperationException`.

### Configure with a DomainResolver

Call `WithCustomDomains()` and provide a `DomainResolver` to resolve the domain dynamically based on the incoming request. The domain can be derived from a subdomain, request header, query parameter, or any other request attribute:

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
})
.WithCustomDomains(options =>
{
    // Example: resolve from a custom header
    options.DomainResolver = httpContext =>
    {
        var tenant = httpContext.Request.Headers["X-Tenant-Domain"].FirstOrDefault();
        return Task.FromResult(tenant ?? "default-tenant.auth0.com");
    };
});
```

### Resolve domain from subdomain

```csharp
services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = Configuration["Auth0:Domain"];
    options.ClientId = Configuration["Auth0:ClientId"];
})
.WithCustomDomains(options =>
{
    // e.g., "acme.myapp.com" -> "acme.auth0.com"
    options.DomainResolver = httpContext =>
    {
        var host = httpContext.Request.Host.Host;
        var subdomain = host.Split('.')[0];
        return Task.FromResult($"{subdomain}.auth0.com");
    };
});
```

### Redirect URI requirements

When using MCD, the `redirectUri` must be an **absolute URL**. In MCD deployments, you will typically resolve the redirect URI per request so each domain uses the correct callback URL:

```csharp
var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
    // Resolve redirect URI based on the incoming request's host
    .WithRedirectUri($"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/callback")
    .Build();

await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
```

You must validate the host and scheme safely for your deployment to prevent open redirect attacks.

### Legacy sessions and migration

When moving from a static domain setup to a `DomainResolver`, existing sessions can continue to work if the resolver returns the same Auth0 custom domain that was used for those legacy sessions.

If the resolver returns a different domain, the SDK treats the session as missing and requires the user to sign in again. This is intentional to keep sessions isolated per domain.

### Security requirements

When configuring the `DomainResolver`, you are responsible for ensuring that all resolved domains are trusted. Mis-configuring the domain resolver is a critical security risk that can lead to authentication bypass on the relying party (RP) or expose the application to Server-Side Request Forgery (SSRF).

**Single tenant limitation:**
The `DomainResolver` is intended solely for multiple custom domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

**Secure proxy requirement:**
When using MCD, your application must be deployed behind a secure edge or reverse proxy (e.g., Cloudflare, Nginx, or AWS ALB). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in malicious redirects, where users are sent to unauthorized or fraudulent endpoints during the login and logout flows.

### Configuration Manager Cache

You can control how OpenID Connect configuration managers are cached per domain with `ConfigurationManagerCache`.

By default, the SDK uses an in-memory cache with:
- `maxSize: 100` entries
- No expiration (entries remain until evicted by size pressure)

The cache is keyed by the OIDC metadata endpoint URL (e.g., `https://brand-1.custom-domain.com/.well-known/openid-configuration`). Each distinct domain resolved by `DomainResolver` occupies one cache entry.

Most applications can keep the defaults, but you may want to adjust them in the following cases:
- Increase `maxSize` if one process may verify tokens for more than 100 distinct domains during its lifetime.
- Decrease `maxSize` if memory usage matters more than avoiding repeated OIDC discovery setup.
- Set `slidingExpiration` if you want entries that haven't been accessed within a given duration to be evicted automatically.
- Use `NullConfigurationManagerCache` to disable caching entirely (not recommended for production).

Rule of thumb: set `maxSize` to cover the number of distinct domains a single process is expected to serve, with some headroom.

#### MemoryConfigurationManagerCache (Default)

```csharp
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };

    options.ConfigurationManagerCache = new MemoryConfigurationManagerCache(
        maxSize: 100,                             // Maximum number of domains to cache
        slidingExpiration: TimeSpan.FromHours(1)  // Optional: evict entries not accessed within 1 hour
    );
});
```

#### NullConfigurationManagerCache

Disables caching entirely — a new configuration manager is created on every request (not recommended for production):

```csharp
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };
    options.ConfigurationManagerCache = new NullConfigurationManagerCache();
});
```

#### Custom Cache Implementation

Implement `IConfigurationManagerCache` for custom caching strategies (e.g., a distributed cache):

```csharp
public class MyCustomConfigurationManagerCache : IConfigurationManagerCache
{
    public IConfigurationManager<OpenIdConnectConfiguration> GetOrCreate(
        string metadataAddress,
        Func<string, IConfigurationManager<OpenIdConnectConfiguration>> factory)
    {
        // Return a cached instance or call factory(metadataAddress) to create one
    }

    public void Clear() { /* Evict all entries */ }
    public void Dispose() { /* Clean up resources */ }
}

// Usage
.WithCustomDomains(options =>
{
    options.DomainResolver = httpContext => { /* ... */ };
    options.ConfigurationManagerCache = new MyCustomConfigurationManagerCache();
});
```

## Backchannel Logout

Backchannel logout can be configured by calling `WithBackchannelLogout()` when calling `AddAuth0WebAppAuthentication`.

```csharp
services
    .AddAuth0WebAppAuthentication(PlaygroundConstants.AuthenticationScheme, options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
    }).WithBackchannelLogout();

```

Additionally, you will also need to call `UseBackchannelLogout();` on the ApplicationBuilder:

```csharp
app.UseBackchannelLogout();
```

When using a custom scheme, make sure to use the same scheme name consistently throughout your authentication flow (login, logout, and backchannel logout configuration).

As logout tokens need to be stored, you will also need to provide something for our SDK to store the tokens in.

```csharp
services.AddTransient<ILogoutTokenHandler, CustomLogoutTokenHandler>();
```

The implementation of `CustomLogoutTokenHandler` will heaviliy depend on your situation, but here's a blueprint you can use:

```csharp
 public class CustomLogoutTokenHandler : ILogoutTokenHandler
{
    public CustomLogoutTokenHandler()
    {
    }

    public Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
    {
        // When a token is received, you need to store it for the duration of `expiration`, using `issuer` and `sid` as the identifiers.
    }

    public Task<bool> IsLoggedOutAsync(string issuer, string sid)
    {
        // Return a boolean based on whether or not you find a logout token using the `issuer` and `sid`.
    }
}
```

### Distributed caching
If you want to connect the backchannel logout to a [distributed cache](https://learn.microsoft.com/en-us/aspnet/core/performance/caching/distributed), such as redis, to store the logout tokens, you can use:

```csharp
public class CustomDistributedLogoutTokenHandler : ILogoutTokenHandler
{
    private readonly IDistributedCache _cache;

    public CustomDistributedLogoutTokenHandler(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task OnTokenReceivedAsync(string issuer, string sid, string logoutToken, TimeSpan expiration)
    {
        await _cache.SetAsync($"{issuer}|{sid}", Encoding.ASCII.GetBytes(logoutToken), new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = expiration
        });
    }

    public async Task<bool> IsLoggedOutAsync(string issuer, string sid)
    {
        var token = await _cache.GetAsync($"{issuer}|{sid}");
        return token != null;
    }
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
