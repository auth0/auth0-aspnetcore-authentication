using System;
using System.Text.Json;
using Auth0.AspNetCore.Authentication.BackchannelLogout;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure
{
    /// <summary>
    /// Helper class to create an instance of the TestServer to use for Integration Tests.
    /// </summary>
    internal class TestServerBuilder
    {
        public static readonly string Host = @"https://localhost";
        public static readonly string Login = "Account/Login";
        public static readonly string Protected = "Account/Claims";
        public static readonly string Process = "Process";
        public static readonly string Logout = "Account/Logout";
        public static readonly string Callback = "Callback";
        public static readonly string Tokens = "Account/Tokens";
        public static readonly string ExtraProviderScheme = "ExtraProviderScheme";

        /// <summary>
        /// Create an instance of the TestServer to use for Integration Tests.
        /// </summary>
        /// <param name="configureOptions">Action used to provide custom configuration for the Auth0 middleware.</param>
        /// <param name="mockAuthentication">Indicated whether or not the authenitcation should be mocked, useful because some tests require an authenticated user while others require no user to exist.</param>
        /// <returns>The created TestServer instance.</returns>
        public static TestServer CreateServer(Action<Auth0WebAppOptions> configureOptions = null, Action<Auth0WebAppWithAccessTokenOptions> configureWithAccessTokensOptions = null, bool mockAuthentication = false, bool useServiceCollectionExtension = false, bool addExtraProvider = false, Action<Auth0WebAppOptions> configureAdditionalOptions = null, bool enableBackchannelLogout = false)
        {
            var configuration = TestConfiguration.GetConfiguration();
            var host = new HostBuilder()
                .ConfigureWebHost(builder =>
                    builder.UseTestServer()
                        .Configure(app =>
                        {
                            app.UseRouting();
                            app.UseAuthentication();
                            app.UseAuthorization();

                            if (enableBackchannelLogout)
                            {
                                app.UseBackchannelLogout();
                            }

                            app.Use(async (context, next) =>
                            {
                                var req = context.Request;
                                var res = context.Response;

                               if (req.Path == new PathString("/process"))
                                {
                                    var ticket = await context.AuthenticateAsync("Cookies");
                                    await res.WriteAsync(JsonSerializer.Serialize(new
                                    {
                                        RefreshToken = await context.GetTokenAsync("refresh_token")
                                    }));
                                }
                                else
                                {
                                    await next();
                                }
                            });
                            app.UseEndpoints(endpoints =>
                            {
                                endpoints.MapControllerRoute(
                                    name: "default",
                                    pattern: "{controller=Home}/{action=Index}/{id?}");
                            });
                        })
                        .ConfigureServices(services =>
                        {
                            Auth0WebAppAuthenticationBuilder builder;
                            if (useServiceCollectionExtension)
                            {
                                builder = services.AddAuth0WebAppAuthentication(options =>
                                {
                                    options.Domain = configuration["Auth0:Domain"];
                                    options.ClientId = configuration["Auth0:ClientId"];

                                    if (configureOptions != null) configureOptions(options);
                                });
                            }
                            else
                            {
                                var authenticationBuilder = services.AddAuthentication(options =>
                                {
                                    if (!mockAuthentication)
                                    {
                                        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                    }
                                });

                                builder = authenticationBuilder.AddAuth0WebAppAuthentication(options =>
                                {
                                    options.Domain = configuration["Auth0:Domain"];
                                    options.ClientId = configuration["Auth0:ClientId"];

                                    if (configureOptions != null) configureOptions(options);
                                });

                                if (addExtraProvider)
                                {
                                    authenticationBuilder.AddAuth0WebAppAuthentication(ExtraProviderScheme, options =>
                                    {
                                        options.Domain = configuration["Auth0:ExtraProvider:Domain"];
                                        options.ClientId = configuration["Auth0:ExtraProvider:ClientId"];
                                        options.SkipCookieMiddleware = true;

                                        if (configureAdditionalOptions != null) configureAdditionalOptions(options);
                                    });
                                }
                            }

                            if (configureWithAccessTokensOptions != null)
                            {
                                builder.WithAccessToken(configureWithAccessTokensOptions);
                            }
                            
                            if (enableBackchannelLogout)
                            {
                                builder.WithBackchannelLogout();
                            }

                            services.AddControllersWithViews();
                        })
                        .ConfigureTestServices(services =>
                        {
                            if (mockAuthentication)
                            {
                                services.AddAuthentication("Test")
                                    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(
                                        "Test", options => { });
                            }
                        })
                        .UseConfiguration(configuration))

                .Build();

            host.Start();
            return host.GetTestServer();
        }
    }
}

