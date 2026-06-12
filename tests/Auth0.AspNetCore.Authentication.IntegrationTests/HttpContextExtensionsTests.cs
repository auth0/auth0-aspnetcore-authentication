using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
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

        [Fact]
        public async Task GetAccessTokenAsync_WithCorruptedAccessTokenSets_TreatsAsCacheMissAndRefreshes()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";
            // Corrupted/version-skewed additional-token store.
            properties.Items[".Token.access_tokens"] = "{ this is not valid json";

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://other-api" });

            // Corruption is swallowed: the request falls through to a refresh rather than throwing.
            result.Should().Be("fresh");
        }

        [Fact]
        public async Task GetAccessTokenAsync_WithMalformedPrimaryExpiry_TreatsAsExpiredAndRefreshes()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = "not-a-date";
            properties.Items[".Token.refresh_token"] = "rt";

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience });

            result.Should().Be("fresh");
            handler.Protected().Verify("SendAsync", Times.Once(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        public async Task GetAccessTokenAsync_WhenRefreshRejected_FiresRefreshFailedEventAndReturnsNull()
        {
            var handler = CreateFailingHandler(HttpStatusCode.BadRequest,
                "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token revoked\"}");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? captured = null;
            var context = BuildContext(handler.Object, properties, out _, opts =>
            {
                opts.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = ctx =>
                    {
                        captured = ctx;
                        return Task.CompletedTask;
                    }
                };
            });

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().BeNull();
            captured.Should().NotBeNull();
            captured!.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
            captured.Error.Should().Be("invalid_grant");
            captured.ErrorDescription.Should().Be("refresh token revoked");
            captured.Exception.Should().BeNull();
            captured.Audience.Should().Be(PrimaryAudience);
            captured.HttpContext.Should().BeSameAs(context);
        }

        [Fact]
        public async Task GetAccessTokenAsync_WhenTransportFails_FiresRefreshFailedEventAndReturnsNull()
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new HttpRequestException("network down"));

            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? captured = null;
            var context = BuildContext(handler.Object, properties, out _, opts =>
            {
                opts.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = ctx =>
                    {
                        captured = ctx;
                        return Task.CompletedTask;
                    }
                };
            });

            // A transport failure must not propagate out of the public method.
            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().BeNull();
            captured.Should().NotBeNull();
            // Transport failures surface as the thrown exception, with no HTTP status/error detail.
            captured!.Exception.Should().BeOfType<HttpRequestException>();
            captured.StatusCode.Should().BeNull();
            captured.Error.Should().BeNull();
        }

        [Fact]
        public async Task GetAccessTokenAsync_AdditionalAudienceCached_ReturnsCachedTokenWithoutCallingBackchannel()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[".Token.access_tokens"] = SerializeSets(
                new AccessTokenSet
                {
                    Audience = "https://other-api",
                    AccessToken = "cached-other",
                    Scope = "read:other",
                    RequestedScope = "read:other",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
                });

            var context = BuildContext(handler.Object, properties, out var authService);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://other-api", Scope = "read:other" });

            result.Should().Be("cached-other");
            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
        }

        [Fact]
        public async Task GetAccessTokenAsync_AdditionalAudienceCached_PrefersSmallestSuperset()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[".Token.access_tokens"] = SerializeSets(
                new AccessTokenSet
                {
                    Audience = "https://other-api",
                    AccessToken = "broad",
                    Scope = "read write",
                    RequestedScope = "read write",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
                },
                new AccessTokenSet
                {
                    Audience = "https://other-api",
                    AccessToken = "narrow",
                    Scope = "read",
                    RequestedScope = "read",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
                });

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://other-api", Scope = "read" });

            // Both tokens satisfy "read", but the least-scoped one must be returned.
            result.Should().Be("narrow");
            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        public async Task GetAccessTokenAsync_AdditionalAudienceWithinLeeway_TreatsAsExpiredAndRefreshes()
        {
            var handler = CreateTokenHandler("fresh");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";
            // Token still valid on the wall clock (expires in 30s) but inside the 60s leeway window.
            properties.Items[".Token.access_tokens"] = SerializeSets(
                new AccessTokenSet
                {
                    Audience = "https://other-api",
                    AccessToken = "almost-expired",
                    Scope = "read:other",
                    RequestedScope = "read:other",
                    ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds()
                });

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://other-api", Scope = "read:other" });

            result.Should().Be("fresh");
            handler.Protected().Verify("SendAsync", Times.Once(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        public async Task GetAccessTokenAsync_OnRefresh_PersistsRotatedRefreshToken()
        {
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":86400,\"refresh_token\":\"rotated-rt\"}");
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
            persisted.Should().NotBeNull();
            persisted!.Items[".Token.refresh_token"].Should().Be("rotated-rt");
        }

        [Fact]
        public async Task GetAccessTokenAsync_OnAdditionalAudienceRefresh_PersistsRotatedIdToken()
        {
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":86400,\"id_token\":\"rotated-id\"}");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.id_token"] = "old-id";
            properties.Items[".Token.refresh_token"] = "rt";

            AuthenticationProperties? persisted = null;
            var context = BuildContext(handler.Object, properties, out var authService);
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
                    (_, _, _, p) => persisted = p)
                .Returns(Task.CompletedTask);

            // A non-primary audience goes through the additional-token path; id_token refresh
            // must still be persisted regardless of which slot was updated.
            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://other-api", Scope = "read:other" });

            result.Should().Be("fresh");
            persisted.Should().NotBeNull();
            persisted!.Items[".Token.id_token"].Should().Be("rotated-id");
        }

        [Fact]
        public async Task GetAccessTokenAsync_WithScopeByAudience_AppliesPerAudienceDefaultScope()
        {
            var capturedBody = string.Empty;
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    if (req.Content != null)
                        capturedBody = req.Content.ReadAsStringAsync().Result;
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":86400,\"scope\":\"read:orders\"}")
                });

            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "primary";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            var context = BuildContext(handler.Object, properties, out _, opts =>
            {
                opts.ScopeByAudience = new Dictionary<string, string> { ["https://orders"] = "read:orders" };
            });

            // No explicit scope on the request — the per-audience default must flow into the exchange.
            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://orders" });

            result.Should().Be("fresh");
            capturedBody.Should().Contain("scope=read%3Aorders");
        }

        private static string SerializeSets(params AccessTokenSet[] sets)
        {
            return JsonSerializer.Serialize(new List<AccessTokenSet>(sets));
        }

        private static Mock<HttpMessageHandler> CreateFailingHandler(HttpStatusCode statusCode, string body)
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
                    StatusCode = statusCode,
                    Content = new StringContent(body)
                });
            return handler;
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

        private static Mock<HttpMessageHandler> CreateRawTokenHandler(string body)
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
                    Content = new StringContent(body)
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
