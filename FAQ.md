# Frequently Asked Questions
- [Reverse Proxy](#reverse-proxy)
  
## Reverse Proxy

It may happen that you are using our SDK with an application that is running behind a reverse proxy. If that is the case, and the Redirect Uri is not the one you'd expect (e.g. `http` instead of `https`, or an incorrect domain such as `localhost`, `127.0.0.1` or anything unexpected), you want to ensure both the reverse proxy and ASP.NET are configured correctly.

Here are some helpful resources:
- https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-8.0
- https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/linux-nginx?view=aspnetcore-8.0&tabs=linux-ubuntu#configure-nginx

Additionally, to help troubleshoot, you can have a look at what is going on:

- `CallbackPath = "/callback"` is passed to our SDK (or omits it to use `/callback` as a default)
- Our SDK passes it down to the ASP.NET Framework as-is [here](https://github.com/auth0/auth0-aspnetcore-authentication/blob/main/src/Auth0.AspNetCore.Authentication/AuthenticationBuilderExtensions.cs#L93), and this is then passed to `BuildRedirectUri` inside the ASP.NET Framework [here](https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectHandler.cs#L403)
- The `BuildRedirectUri` looks like [this](https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/Core/src/AuthenticationHandler.cs#L196-L197).

What is going on is that the reverse proxy is misconfigured and `Request.Host` or `Request.Scheme` show incorrect values because the ForwardHeaders are not configured correctly. You can verify this by looking at the value of `Request.Host` and `Request.Scheme` in any of your own code.
