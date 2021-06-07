# Examples

- [Refresh Token](#refresh-tokens)

## Refresh Tokens

In the case where the application needs to use an Access Token to access an API, there may be a situation where the Access Token  expires before the application's session does. In order to ensure the Access Token is valid for the entire duration of the session, you can configure the SDK to use Refresh Tokens:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuth0Mvc(options =>
    {
        options.Domain = Configuration["Auth0:Domain"];
        options.ClientId = Configuration["Auth0:ClientId"];
        options.ClientSecret = Configuration["Auth0:ClientSecret"];
        options.Audience = Configuration["Auth0:Audience"];
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UseRefreshTokens = true;
    });
}
```

> :information_source: In order to use Refresh Tokens, the application needs to use an `Audience`, a `ClientSecret` and set the `ResponseType` to `OpenIdConnectResponseType.Code`.


### Detecting the absense of a Refresh Token

In the event where the API isn't configured to allow offline usage, or the user was already logged in before the use of Refresh Tokens was enabled (e.g. a user logs in a few minutes before the use of refresh tokens is deployed), it might be useful to detect the absense of a Refresh Token in order to react accordingly (e.g. log the user out and force them to re-login).

```
app.Use(async (context, next) =>
{
    var idToken = await context.GetTokenAsync("id_token");
    var refreshToken = await context.GetTokenAsync("refresh_token");
    var options = context.RequestServices.GetRequiredService<Auth0Options>();

    if (options.UseRefreshTokens && !string.IsNullOrEmpty(idToken) && string.IsNullOrEmpty(refreshToken))
    {
        var authenticationProperties = new AuthenticationPropertiesBuilder()
            .WithRedirectUri("/Account/Login")
            .Build();

        await context.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    await next();
});
```

The above snippet checks whether the SDK is configured to use Refresh Tokens, if there is an existing Id Token (meaning the user is authenticaed) as well as the absense of a Refresh Token. If each of these criteria are met, it logs the user out, configuring the login URL as a redirect URL.

> :information_source: In order for Auth0 to redirect back to the application's login URL, ensure to add the configured redirect URL to the application's `Allowed Logout URLs` in Auth0's dashboard.

