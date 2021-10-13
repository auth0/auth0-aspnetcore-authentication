# Migrating to Auth0.AspNetCore.Authentication
When your application is currently using `Microsoft.AspNetCore.Authentication.OpenIdConnect` and you would like to migrate to Auth0's SDK for ASP.NET Core, there are a few things to take into considerations:

## Basic configuration
A typical basic integration of Auth0 in your ASP.NET Core application would use the following code to configure Microsoft's `OpenIdConnect` middleware.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options => {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect("Auth0", options => {
        options.Authority = $"https://{Configuration["Auth0:Domain"]}";
        options.ClientId = Configuration["Auth0:ClientId"];
        options.CallbackPath = new PathString("/callback");
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name"
        };
        options.Events = new OpenIdConnectEvents
        {
            OnRedirectToIdentityProviderForSignOut = (context) =>
            {
                var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

                var postLogoutUri = context.Properties.RedirectUri;
                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    if (postLogoutUri.StartsWith("/"))
                    {
                        var request = context.Request;
                        postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                    }
                    logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                }

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            }
        };
    });
    });
}
```

There is a lot going on above, and we aren't going into detail here, but it can be simplified quite a bit when using our SDK:

- Call `services.AddAuth0WebAppAuthentication(...)` instead of `services.AddAuthentication(...).AddCookie().AddOpenIdConnect(...)`.
- Drop the `TokenValidationParameters`.
- Specify `Domain` instead of `Authority`.
- `CallbackPath` uses `/callback` by default when using our SDK, but you can overwrite it if needed.
- There is no need to configure the Logout URL anymore, so you should be able to remove `OnRedirectToIdentityProviderForSignOut`, as our SDK takes care of that internally.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuth0WebAppAuthentication(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
    });
}
```

**Obtain an Access Token for Calling an API**
If you need to call an API from your MVC application, you need to obtain an Access Token issued for the API you want to call.
To obtain the token, pass an additional audience parameter containing the API Identifier to the Auth0 authorization endpoint.
With Microsoft's `OpenIdConnect` middleware, this can be done by setting the `audience` parameter on the `ProtocolMessage`

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuthentication(...)
        .AddCookie()
        .AddOpenIdConnect("Auth0", options => {
            /* Code omitted for Basic configuration to Login  */
            options.ClientSecret = Configuration["Auth0:ClientSecret"];
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = context =>
                {
                    context.ProtocolMessage.SetParameter("audience", Configuration["Auth0:Audience"]);

                    return Task.FromResult(0);
                }
            };
        });
}
```

Even though the above snippet isn't exactly complicated, using our SDK this can be slightly simplified to:

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
        });
}
```

Important here is that, to retrieve an Access Token, you will need to ensure you specify a Client Secret when calling `AddAuth0WebAppAuthentication`.

**Custom Open ID Connect Event Handlers**
When using Microsoft's OpenIdConnect middleware, there are several [events](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.openidconnect.openidconnectevents?view=aspnetcore-5.0) that you can use to hook into to customize the middleware based on your specific needs.


```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuthentication(...)
        .AddCookie()
        .AddOpenIdConnect("Auth0", options => {
            options.Events.OnTokenValidated = context =>
            {
                return Task.CompletedTask;
            };
        });
}
```
All of these events are exposed through [Auth0WebAppOptions.OpenIdConnectEvents](https://auth0.github.io/auth0-aspnetcore-authentication/api/Auth0.AspNetCore.Authentication.Auth0WebAppOptions.html#Auth0_AspNetCore_Authentication_Auth0WebAppOptions_OpenIdConnectEvents), so you can migrate your code pretty easily by moving all of the event handlers to the corresponding property on `OpenIdConnectEvents`.

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services
        .AddAuth0WebAppAuthentication(options =>
        {
            options.OpenIdConnectEvents = new OpenIdConnectEvents
            {
                OnTokenValidated = (context) =>
                {
                    return Task.CompletedTask;
                }
            };
        });
}
```