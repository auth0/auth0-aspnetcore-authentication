using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class HttpContextExtensionsTests
    {
        private const string CookieScheme = "Cookies";
        private const string Domain = "test.auth0.com";
        private const string PrimaryAudience = "https://api";

        [Fact]
        public async Task GetAccessTokenAsync_WithoutForceRefresh_ReturnsCachedTokenWithoutCallingBackchannel()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            var context = BuildContext(handler.Object, properties, out var authService);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = false });

            result.Should().Be("cached");
            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
        }

        [Fact]
        public async Task GetAccessTokenAsync_WithForceRefresh_BypassesCacheAndPersistsNewToken()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AuthenticationProperties? persisted = null;
            var context = BuildContext(handler.Object, properties, out var authService);
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
                    (_, _, _, p) => persisted = p)
                .Returns(Task.CompletedTask);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().Be("fresh");
            handler.Protected().Verify("SendAsync", Times.Once(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
            persisted.Should().NotBeNull();
            persisted!.Items[".Token.access_token"].Should().Be("fresh");
        }

        [Fact]
        public async Task GetAccessTokenAsync_WithForceRefresh_NoRefreshToken_FiresEventAndReturnsNull()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            // No refresh token stored.

            var missingRefreshTokenFired = false;
            var context = BuildContext(handler.Object, properties, out _, withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnMissingRefreshToken = _ =>
                    {
                        missingRefreshTokenFired = true;
                        return Task.CompletedTask;
                    }
                };
            });

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().BeNull();
            missingRefreshTokenFired.Should().BeTrue();
            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        private static Mock<HttpMessageHandler> CreateTokenHandler(string accessToken)
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"Bearer\",\"expires_in\":86400}}")
                });
            return handler;
        }

        private static HttpContext BuildContext(
            HttpMessageHandler backchannelHandler,
            AuthenticationProperties properties,
            out Mock<IAuthenticationService> authService,
            Action<Auth0WebAppWithAccessTokenOptions>? configureWithAccessToken = null)
        {
            var webAppOptions = new Auth0WebAppOptions
            {
                Domain = Domain,
                ClientId = "cid",
                ClientSecret = "secret",
                Backchannel = new HttpClient(backchannelHandler),
                CookieAuthenticationScheme = CookieScheme
            };

            var withAccessTokenOptions = new Auth0WebAppWithAccessTokenOptions
            {
                Audience = PrimaryAudience
            };
            configureWithAccessToken?.Invoke(withAccessTokenOptions);

            var principal = new ClaimsPrincipal(new ClaimsIdentity("Cookies"));
            var ticket = new AuthenticationTicket(principal, properties, CookieScheme);

            authService = new Mock<IAuthenticationService>();
            authService
                .Setup(s => s.AuthenticateAsync(It.IsAny<HttpContext>(), CookieScheme))
                .ReturnsAsync(AuthenticateResult.Success(ticket));
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Returns(Task.CompletedTask);

            var webAppSnapshot = new Mock<IOptionsSnapshot<Auth0WebAppOptions>>();
            webAppSnapshot.Setup(s => s.Get(It.IsAny<string>())).Returns(webAppOptions);
            var withAccessTokenSnapshot = new Mock<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>();
            withAccessTokenSnapshot.Setup(s => s.Get(It.IsAny<string>())).Returns(withAccessTokenOptions);

            var services = new ServiceCollection();
            services.AddSingleton(authService.Object);
            services.AddSingleton(webAppSnapshot.Object);
            services.AddSingleton(withAccessTokenSnapshot.Object);

            return new DefaultHttpContext
            {
                RequestServices = services.BuildServiceProvider()
            };
        }
    }
}
