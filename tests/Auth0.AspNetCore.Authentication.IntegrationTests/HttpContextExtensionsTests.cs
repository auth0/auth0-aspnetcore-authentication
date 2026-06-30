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
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Microsoft.AspNetCore.DataProtection;

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
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: withAccessTokenOptions =>
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
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: opts =>
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
        public async Task GetAccessTokenAsync_WhenRefreshReturnsTokenlessBody_FiresRefreshFailedEventAndDoesNotPersist()
        {
            // 200 OK with no access_token: must be treated as a failure, not a success that
            // clobbers the cached primary token with null.
            var handler = CreateRawTokenHandler("{}");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? captured = null;
            var context = BuildContext(handler.Object, properties, out var authService, configureWithAccessToken: opts =>
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
            captured!.StatusCode.Should().Be((int)HttpStatusCode.OK);
            captured.Error.Should().Be("invalid_token_response");
            captured.ErrorDescription.Should().Be("The token endpoint returned a response without an access token.");
            // The session must be left untouched — no SignInAsync, so the stale token is preserved.
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
            properties.Items[".Token.access_token"].Should().Be("cached");
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
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: opts =>
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

            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: opts =>
            {
                opts.ScopeByAudience = new Dictionary<string, string> { ["https://orders"] = "read:orders" };
            });

            // No explicit scope on the request — the per-audience default must flow into the exchange.
            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = "https://orders" });

            result.Should().Be("fresh");
            capturedBody.Should().Contain("scope=read%3Aorders");
        }

        [Fact]
        public async Task GetAccessTokenAsync_WhenMfaRequired_ThrowsMfaRequiredException_AndDoesNotFireRefreshFailed()
        {
            var handler = CreateMfaRequiredHandler();
            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            var refreshFailedFired = false;
            var protector = new MfaTokenProtector(new EphemeralDataProtectionProvider());
            var context = BuildContext(handler.Object, properties, out _, protector, configureWithAccessToken: withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = _ => { refreshFailedFired = true; return Task.CompletedTask; }
                };
            });

            var act = async () => await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            var ex = await act.Should().ThrowAsync<MfaRequiredException>();
            ex.And.MfaToken.Should().NotBe("the-mfa-token");
            ex.And.MfaToken.Should().NotBeNullOrEmpty();
            protector.Unprotect(ex.And.MfaToken!).MfaToken.Should().Be("the-mfa-token");
            refreshFailedFired.Should().BeFalse();
        }

        [Fact]
        public async Task GetAccessTokenAsync_WhenMfaRequiredWithoutToken_FiresRefreshFailed_AndDoesNotThrow()
        {
            // A mfa_required response with no mfa_token is malformed: it cannot drive the MFA
            // flow, so it must be treated as a refresh failure rather than throwing a
            // MfaRequiredException carrying an un-unprotectable blob.
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.Forbidden,
                    Content = new StringContent("{\"error\":\"mfa_required\",\"error_description\":\"Multifactor authentication required\"}")
                });

            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? failedContext = null;
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = c => { failedContext = c; return Task.CompletedTask; }
                };
            });

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().BeNull();
            failedContext.Should().NotBeNull();
            failedContext!.Error.Should().Be("mfa_required");
        }

        [Fact]
        public async Task GetAccessTokenAsync_WhenOtherError_FiresRefreshFailed_AndDoesNotThrow()
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.Forbidden,
                    Content = new StringContent("{\"error\":\"invalid_grant\",\"error_description\":\"token revoked\"}")
                });

            var properties = new AuthenticationProperties();
            properties.Items[".Token.access_token"] = "cached";
            properties.Items[".Token.expires_at"] = DateTimeOffset.Now.AddHours(1).ToString("o");
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? failedContext = null;
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = c => { failedContext = c; return Task.CompletedTask; }
                };
            });

            var result = await context.GetAccessTokenAsync(
                new AccessTokenRequest { Audience = PrimaryAudience, ForceRefresh = true });

            result.Should().BeNull();
            failedContext.Should().NotBeNull();
            failedContext!.Error.Should().Be("invalid_grant");
        }

        private static string SerializeSets(params AccessTokenSet[] sets)
        {
            return JsonSerializer.Serialize(new List<AccessTokenSet>(sets));
        }

        private static Mock<HttpMessageHandler> CreateMfaRequiredHandler()
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
                    StatusCode = HttpStatusCode.Forbidden,
                    Content = new StringContent(
                        "{\"error\":\"mfa_required\",\"error_description\":\"Multifactor authentication required\",\"mfa_token\":\"the-mfa-token\"}")
                });
            return handler;
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

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_WithCachedToken_ReturnsCachedWithoutCallingBackchannel()
        {
            // A handler that would throw if called — proves the cache short-circuits the grant.
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new InvalidOperationException("backchannel should not be called on a cache hit"));

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[HttpContextExtensions.ConnectionTokensItemKey] = JsonSerializer.Serialize(new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet
                {
                    Connection = "google-oauth2",
                    AccessToken = "cached_google_token",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                    Scope = "email"
                }
            });

            var context = BuildContext(handler.Object, properties, out var authService);

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2" });

            result.Should().Be("cached_google_token");
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_WithForceRefresh_BypassesCacheAndPersistsNewToken()
        {
            var handler = CreateRawTokenHandler("{\"access_token\":\"fresh_google_token\",\"expires_in\":3600,\"scope\":\"email\"}");

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[HttpContextExtensions.ConnectionTokensItemKey] = JsonSerializer.Serialize(new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet
                {
                    Connection = "google-oauth2",
                    AccessToken = "stale_cached_token",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
                }
            });

            AuthenticationProperties? persisted = null;
            var context = BuildContext(handler.Object, properties, out var authService);
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
                    (_, _, _, p) => persisted = p)
                .Returns(Task.CompletedTask);

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2", ForceRefresh = true });

            result.Should().Be("fresh_google_token");
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Once());
            persisted.Should().NotBeNull();
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_DifferentLoginHint_DoesNotReturnOtherIdentitysCachedToken()
        {
            // Identity A's token is cached for the connection. A request for identity B on the
            // same connection must not be served A's token from the cache — it must exchange and
            // return B's own token.
            var handler = CreateRawTokenHandler("{\"access_token\":\"identityB_token\",\"expires_in\":3600,\"scope\":\"email\"}");

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[HttpContextExtensions.ConnectionTokensItemKey] = JsonSerializer.Serialize(new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet
                {
                    Connection = "google-oauth2",
                    LoginHint = "identityA",
                    AccessToken = "identityA_token",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                    Scope = "email"
                }
            });

            AuthenticationProperties? persisted = null;
            var context = BuildContext(handler.Object, properties, out var authService);
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
                    (_, _, _, p) => persisted = p)
                .Returns(Task.CompletedTask);

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2", LoginHint = "identityB" });

            result.Should().Be("identityB_token");
            result.Should().NotBe("identityA_token");

            // Both identities should now be cached side by side under the one connection.
            persisted.Should().NotBeNull();
            var stored = JsonSerializer.Deserialize<List<ConnectionTokenSet>>(
                persisted!.Items[HttpContextExtensions.ConnectionTokensItemKey]!);
            stored.Should().HaveCount(2);
            stored.Should().Contain(s => s.LoginHint == "identityA" && s.AccessToken == "identityA_token");
            stored.Should().Contain(s => s.LoginHint == "identityB" && s.AccessToken == "identityB_token");
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_MatchingLoginHint_ReturnsCachedWithoutCallingBackchannel()
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new InvalidOperationException("backchannel should not be called on a cache hit"));

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[HttpContextExtensions.ConnectionTokensItemKey] = JsonSerializer.Serialize(new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet
                {
                    Connection = "google-oauth2",
                    LoginHint = "identityA",
                    AccessToken = "identityA_token",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                    Scope = "email"
                }
            });

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2", LoginHint = "identityA" });

            result.Should().Be("identityA_token");
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_WhitespaceLoginHint_TreatedSameAsNoHint_ReturnsCachedWithoutCallingBackchannel()
        {
            // An empty/whitespace LoginHint addresses the same default identity as no hint (the token
            // endpoint omits it either way), so it must hit the entry cached with no hint rather than
            // missing the cache and triggering a redundant exchange.
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ThrowsAsync(new InvalidOperationException("backchannel should not be called on a cache hit"));

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[HttpContextExtensions.ConnectionTokensItemKey] = JsonSerializer.Serialize(new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet
                {
                    Connection = "google-oauth2",
                    AccessToken = "no_hint_token",
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
                    Scope = "email"
                }
            });

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2", LoginHint = "   " });

            result.Should().Be("no_hint_token");
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_NoRefreshToken_FiresEventAndReturnsNull()
        {
            var handler = CreateRawTokenHandler("{\"access_token\":\"unused\",\"expires_in\":3600}");

            var properties = new AuthenticationProperties(); // no refresh token

            var missingRefreshTokenFired = false;
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnMissingRefreshToken = _ => { missingRefreshTokenFired = true; return Task.CompletedTask; }
                };
            });

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2" });

            result.Should().BeNull();
            missingRefreshTokenFired.Should().BeTrue();
        }

        [Fact]
        public async Task GetAccessTokenForConnectionAsync_WhenExchangeRejected_FiresRefreshFailedEventAndReturnsNull()
        {
            var handler = CreateFailingHandler(HttpStatusCode.BadRequest, "{\"error\":\"invalid_request\",\"error_description\":\"no linked account\"}");

            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";

            AccessTokenRefreshFailedContext? failedContext = null;
            var context = BuildContext(handler.Object, properties, out _, configureWithAccessToken: withAccessTokenOptions =>
            {
                withAccessTokenOptions.Events = new Auth0WebAppWithAccessTokenEvents
                {
                    OnAccessTokenRefreshFailed = c => { failedContext = c; return Task.CompletedTask; }
                };
            });

            var result = await context.GetAccessTokenForConnectionAsync(
                new AccessTokenForConnectionRequest { Connection = "google-oauth2" });

            result.Should().BeNull();
            failedContext.Should().NotBeNull();
            failedContext!.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_OnSuccess_MapsResponseToResult()
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
                        "{\"access_token\":\"at\",\"id_token\":\"id\",\"refresh_token\":\"rt\",\"expires_in\":3600,\"scope\":\"read:data\"}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token"
            });

            result.AccessToken.Should().Be("at");
            result.IdToken.Should().Be("id");
            result.RefreshToken.Should().Be("rt");
            result.ExpiresIn.Should().Be(3600);
            result.Scope.Should().Be("read:data");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_OnSuccess_DoesNotEstablishSession()
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
                    Content = new StringContent("{\"access_token\":\"at\",\"expires_in\":3600}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out var authService);

            await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token"
            });

            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WhenRejected_ThrowsWithErrorDetails()
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
                    StatusCode = HttpStatusCode.Forbidden,
                    Content = new StringContent("{\"error\":\"invalid_request\",\"error_description\":\"bad profile\"}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = async () => await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token"
            });

            var assertion = await act.Should().ThrowAsync<CustomTokenExchangeException>();
            assertion.Which.StatusCode.Should().Be((int)HttpStatusCode.Forbidden);
            assertion.Which.Error.Should().Be("invalid_request");
            assertion.Which.ErrorDescription.Should().Be("bad profile");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_OnInvalidRequest_ThrowsBeforeNetworkCall()
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage { StatusCode = HttpStatusCode.OK });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = async () => await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "",
                SubjectTokenType = "urn:acme:legacy-token"
            });

            await act.Should().ThrowAsync<CustomTokenExchangeException>();
            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_OnDelegation_ExposesActClaim()
        {
            // id_token payload {"sub":"auth0|u","act":{"sub":"mcp_client"}}
            string B64Url(string s)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(s);
                return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
            var idToken = $"{B64Url("{\"alg\":\"RS256\"}")}." +
                          $"{B64Url("{\"sub\":\"auth0|u\",\"act\":{\"sub\":\"mcp_client\"}}")}.sig";

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
                        "{\"access_token\":\"at\",\"id_token\":\"" + idToken + "\",\"expires_in\":3600}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                ActorToken = "act-token",
                ActorTokenType = "urn:acme:actor-token"
            });

            result.Act.Should().NotBeNull();
            result.Act!.Sub.Should().Be("mcp_client");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WithMatchingOrgId_Succeeds()
        {
            var idToken = BuildIdToken("{\"sub\":\"auth0|u\",\"org_id\":\"org_abc123\"}");
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"at\",\"id_token\":\"" + idToken + "\",\"expires_in\":3600}");

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                Organization = "org_abc123"
            });

            result.AccessToken.Should().Be("at");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WithMatchingOrgName_IsCaseInsensitive()
        {
            var idToken = BuildIdToken("{\"sub\":\"auth0|u\",\"org_name\":\"acme\"}");
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"at\",\"id_token\":\"" + idToken + "\",\"expires_in\":3600}");

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                Organization = "ACME"
            });

            result.AccessToken.Should().Be("at");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WithMismatchedOrgId_Throws()
        {
            var idToken = BuildIdToken("{\"sub\":\"auth0|u\",\"org_id\":\"org_other\"}");
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"at\",\"id_token\":\"" + idToken + "\",\"expires_in\":3600}");

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = async () => await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                Organization = "org_abc123"
            });

            await act.Should().ThrowAsync<CustomTokenExchangeException>().WithMessage("*org_id*mismatch*");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WithMissingOrgClaim_Throws()
        {
            var idToken = BuildIdToken("{\"sub\":\"auth0|u\"}");
            var handler = CreateRawTokenHandler(
                "{\"access_token\":\"at\",\"id_token\":\"" + idToken + "\",\"expires_in\":3600}");

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = async () => await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                Organization = "org_abc123"
            });

            await act.Should().ThrowAsync<CustomTokenExchangeException>().WithMessage("*org_id*present*");
        }

        [Fact]
        public async Task CustomTokenExchangeAsync_WithOrgButNoIdToken_DoesNotThrow()
        {
            // No ID token returned (e.g. access-token-only exchange): nothing to validate against.
            var handler = CreateRawTokenHandler("{\"access_token\":\"at\",\"expires_in\":3600}");

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.CustomTokenExchangeAsync(new CustomTokenExchangeRequest
            {
                SubjectToken = "ext-token",
                SubjectTokenType = "urn:acme:legacy-token",
                Organization = "org_abc123"
            });

            result.AccessToken.Should().Be("at");
        }

        private static string BuildIdToken(string payloadJson)
        {
            string B64Url(string s)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(s);
                return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }

            return $"{B64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}")}.{B64Url(payloadJson)}.sig";
        }

        private static HttpContext BuildContext(
            HttpMessageHandler backchannelHandler,
            AuthenticationProperties properties,
            out Mock<IAuthenticationService> authService,
            IMfaTokenProtector? mfaTokenProtector = null,
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
            services.AddSingleton<IMfaTokenProtector>(
                mfaTokenProtector ?? new MfaTokenProtector(new EphemeralDataProtectionProvider()));

            return new DefaultHttpContext
            {
                RequestServices = services.BuildServiceProvider()
            };
        }
    }
}
