using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    internal class TestServerBuilder
    {
        public static readonly string Host = @"https://localhost";
        public static readonly string Login = "Account/Login";
        public static readonly string Protected = "Account/Claims";
        public static readonly string Logout = "Account/Logout";
        public static readonly string Callback = "Callback";

        public static TestServer CreateServer(Action<Auth0Options> configureOptions = null, bool mockAuthentication = false)
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
                            app.UseEndpoints(endpoints =>
                            {
                                endpoints.MapControllerRoute(
                                    name: "default",
                                    pattern: "{controller=Home}/{action=Index}/{id?}");
                            });
                        })
                        .ConfigureServices(services =>
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

