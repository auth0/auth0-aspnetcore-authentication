using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
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

        /// <summary>
        /// Create an instance of the TestServer to use for Integration Tests.
        /// </summary>
        /// <param name="configureOptions">Action used to provide custom configuration for the Auth0 middleware.</param>
        /// <param name="mockAuthentication">Indicated whether or not the authenitcation should be mocked, useful because some tests require an authenticated user while others require no user to exist.</param>
        /// <returns>The created TestServer instance.</returns>
        public static TestServer CreateServer(Action<Auth0Options> configureOptions = null, bool mockAuthentication = false, bool useServiceCollectionExtension = false)
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
                            app.Use(async (context, next) =>
                            {
                                var req = context.Request;
                                var res = context.Response;

                               if (req.Path == new PathString("/process"))
                                {
                                    var ticket = await context.AuthenticateAsync("Cookies");
                                    return;
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
                            if (useServiceCollectionExtension)
                            {
                                services.AddAuth0Mvc(options =>
                                {
                                    options.Domain = configuration["Auth0:Domain"];
                                    options.ClientId = configuration["Auth0:ClientId"];

                                    if (configureOptions != null) configureOptions(options);
                                });
                            }
                            else
                            {
                                services.AddAuthentication(options =>
                                {
                                    if (!mockAuthentication)
                                    {
                                        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                    }
                                }).AddAuth0Mvc(options =>
                                {
                                    options.Domain = configuration["Auth0:Domain"];
                                    options.ClientId = configuration["Auth0:ClientId"];

                                    if (configureOptions != null) configureOptions(options);
                                });
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

