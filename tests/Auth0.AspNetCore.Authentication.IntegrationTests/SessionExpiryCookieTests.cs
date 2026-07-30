using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    /// <summary>
    /// Integration tests for the IPSIE <c>session_expiry</c> read-gate that lives in the cookie
    /// handler's <c>OnValidatePrincipal</c> (wired by <c>AddAuth0WebAppAuthentication</c>).
    ///
    /// The gate only fires when a previously-issued cookie is read back, so each test first mints a
    /// real authentication cookie carrying a chosen <c>auth0:session_expiry</c> item (via a /signin
    /// endpoint), then replays that cookie against a /read endpoint that calls
    /// <see cref="AuthenticationHttpContextExtensions.AuthenticateAsync(HttpContext, string)"/> to
    /// trigger the gate. The response reports whether the session survived.
    ///
    /// Coverage mirrors the "positive / false-positive / negative" shape:
    ///  - positive:        a live ceiling in the future -> session is honored.
    ///  - negative:        a ceiling in the past -> principal rejected, cookie cleared.
    ///  - false-positive:  no ceiling / malformed ceiling -> must NOT be treated as expired
    ///                     (pre-existing sessions and garbage values fall through to normal behavior).
    /// </summary>
    public class SessionExpiryCookieTests
    {
        private const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        private static TestServer CreateServer()
        {
            var configuration = TestConfiguration.GetConfiguration();
            var host = new HostBuilder()
                .ConfigureWebHost(builder =>
                    builder.UseTestServer()
                        .Configure(app =>
                        {
                            app.UseAuthentication();

                            app.Use(async (context, next) =>
                            {
                                var req = context.Request;
                                var res = context.Response;

                                if (req.Path == new PathString("/signin"))
                                {
                                    // Mint a cookie for a fixed user, optionally stamping the persisted
                                    // session_expiry ceiling so we can replay it and observe the gate.
                                    var identity = new ClaimsIdentity(new[]
                                    {
                                        new Claim(ClaimTypes.NameIdentifier, "user-1"),
                                        new Claim("name", "Test User"),
                                    }, CookieScheme);

                                    var principal = new ClaimsPrincipal(identity);
                                    var properties = new AuthenticationProperties();

                                    if (req.Query.TryGetValue("ceiling", out var ceilingValue))
                                    {
                                        properties.Items[Auth0Constants.SessionExpiryItemKey] = ceilingValue.ToString();
                                    }

                                    await context.SignInAsync(CookieScheme, principal, properties);
                                    return;
                                }

                                if (req.Path == new PathString("/read"))
                                {
                                    // Reading the cookie runs OnValidatePrincipal -> the session_expiry gate.
                                    var result = await context.AuthenticateAsync(CookieScheme);
                                    res.StatusCode = (int)HttpStatusCode.OK;
                                    await res.WriteAsync(result.Succeeded ? "authenticated" : "no-session");
                                    return;
                                }

                                await next();
                            });
                        })
                        .ConfigureServices(services =>
                        {
                            services.AddAuthentication(options =>
                                {
                                    options.DefaultAuthenticateScheme = CookieScheme;
                                    options.DefaultSignInScheme = CookieScheme;
                                    options.DefaultChallengeScheme = CookieScheme;
                                })
                                .AddAuth0WebAppAuthentication(options =>
                                {
                                    options.Domain = configuration["Auth0:Domain"];
                                    options.ClientId = configuration["Auth0:ClientId"];
                                });
                        })
                        .UseConfiguration(configuration))
                .Build();

            host.Start();
            return host.GetTestServer();
        }

        private static string Ceiling(TimeSpan fromNow) =>
            (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (long)fromNow.TotalSeconds)
                .ToString(CultureInfo.InvariantCulture);

        private static async Task<(IEnumerable<string> cookies, HttpResponseMessage response)> SignIn(
            TestServer server, string ceiling = null)
        {
            using var client = server.CreateClient();
            var url = ceiling == null
                ? $"{TestServerBuilder.Host}/signin"
                : $"{TestServerBuilder.Host}/signin?ceiling={ceiling}";
            var response = await client.SendAsync(url);
            var cookies = response.Headers.GetValues("Set-Cookie");
            return (cookies, response);
        }

        private static async Task<string> Read(TestServer server, IEnumerable<string> cookies)
        {
            using var client = server.CreateClient();
            var response = await client.SendAsync($"{TestServerBuilder.Host}/read", cookies);
            return await response.Content.ReadAsStringAsync();
        }

        [Fact]
        public async Task Positive_CeilingInFuture_SessionIsHonored()
        {
            using var server = CreateServer();

            var (cookies, _) = await SignIn(server, Ceiling(TimeSpan.FromHours(8)));
            var body = await Read(server, cookies);

            body.Should().Be("authenticated");
        }

        [Fact]
        public async Task Negative_CeilingInPast_SessionIsRejected()
        {
            using var server = CreateServer();

            var (cookies, _) = await SignIn(server, Ceiling(TimeSpan.FromHours(-1)));
            var body = await Read(server, cookies);

            body.Should().Be("no-session");
        }

        [Fact]
        public async Task Negative_CeilingWithinLeewayWindow_SessionIsRejected()
        {
            using var server = CreateServer();

            // The gate applies a negative leeway: at (ceiling - leeway) the session is already expired,
            // so a ceiling only a few seconds in the future is still rejected.
            var justInsideLeeway = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                + Auth0Constants.SessionExpiryLeewaySeconds - 5;
            var (cookies, _) = await SignIn(server, justInsideLeeway.ToString(CultureInfo.InvariantCulture));
            var body = await Read(server, cookies);

            body.Should().Be("no-session");
        }

        [Fact]
        public async Task FalsePositive_NoCeilingPersisted_SessionIsHonored()
        {
            using var server = CreateServer();

            // A session created before this feature has no persisted ceiling: it must never be
            // treated as expired.
            var (cookies, _) = await SignIn(server, ceiling: null);
            var body = await Read(server, cookies);

            body.Should().Be("authenticated");
        }

        [Fact]
        public async Task FalsePositive_MalformedCeiling_SessionIsHonored()
        {
            using var server = CreateServer();

            // A garbage ceiling value must be tolerated as "no ceiling", not fail the read.
            var (cookies, _) = await SignIn(server, "not-a-number");
            var body = await Read(server, cookies);

            body.Should().Be("authenticated");
        }
    }
}
