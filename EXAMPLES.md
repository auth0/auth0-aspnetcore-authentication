# Examples

- [Refresh Token](#refresh-tokens)

## Refresh Tokens

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

> :information_source: In order to use Refresh Tokens, the application needs to use an `Audience`, a `ClientSecret` and set the `ResponseType` to `OpenIdConnectResponseType.Code`.


### Detecting the absense of a Refresh Token

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
                var authenticationProperties = new AuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            }
        };
    });
```

The above snippet checks whether the SDK is configured to use Refresh Tokens, if there is an existing Id Token (meaning the user is authenticaed) as well as the absense of a Refresh Token. If each of these criteria are met, it logs the user out (from the application's side, not from Auth0's side) and initialized a new login flow.

> :information_source: In order for Auth0 to redirect back to the application's login URL, ensure to add the configured redirect URL to the application's `Allowed Logout URLs` in Auth0's dashboard.

