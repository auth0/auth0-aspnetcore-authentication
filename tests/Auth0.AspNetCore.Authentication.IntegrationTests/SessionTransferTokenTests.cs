using FluentAssertions;
using Xunit;
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

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class SessionTransferTokenTests
    {
        private const string CookieScheme = "Cookies";
        private const string Domain = "test.auth0.com";

        private static string B64UrlPayload(string json)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(json);
            var b64 = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return $"eyJhbGciOiJSUzI1NiJ9.{b64}.sig";
        }

        // A JWT-shaped id_token whose exp is `minutesFromNow` in the future.
        private static string IdTokenExpiringIn(int minutesFromNow)
        {
            var exp = DateTimeOffset.UtcNow.AddMinutes(minutesFromNow).ToUnixTimeSeconds();
            return B64UrlPayload($"{{\"sub\":\"agent|1\",\"exp\":{exp}}}");
        }

        private static Mock<HttpMessageHandler> SttHandler(string capturedBodyReceiver = null!)
        {
            // Success handler returning an STT response. Body capture is done via a Callback the caller adds.
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
                        "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60,\"scope\":\"openid\"}")
                });
            return handler;
        }

        private static HttpContext BuildContext(
            HttpMessageHandler backchannelHandler,
            AuthenticationProperties properties,
            out Mock<IAuthenticationService> authService,
            string? resolvedDomain = null,
            string? audience = null)
        {
            var webAppOptions = new Auth0WebAppOptions
            {
                Domain = Domain,
                ClientId = "cid",
                ClientSecret = "secret",
                Backchannel = new HttpClient(backchannelHandler),
                CookieAuthenticationScheme = CookieScheme
            };

            var withAccessTokenOptions = new Auth0WebAppWithAccessTokenOptions { Audience = audience };

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

            var context = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
            if (resolvedDomain != null)
            {
                context.Items[Auth0Constants.ResolvedDomainKey] = resolvedDomain;
            }
            return context;
        }

        [Fact]
        public void CustomTokenExchangeException_CodeConstructor_SetsCodeAndMessage()
        {
            var ex = new CustomTokenExchangeException(CustomTokenExchangeErrorCode.ActorUnavailable, "no actor");

            ex.Code.Should().Be("actor_unavailable");
            ex.Message.Should().Be("no actor");
            ex.StatusCode.Should().BeNull();
        }

        [Fact]
        public void CustomTokenExchangeException_ExistingConstructors_LeaveCodeNull()
        {
            new CustomTokenExchangeException("validation failed").Code.Should().BeNull();
            new CustomTokenExchangeException(400, "err", "desc").Code.Should().BeNull();
        }

        [Fact]
        public void ResolveExplicitActor_ReturnsPair_WithDefaultTypeWhenTypeOmitted()
        {
            var (token, type) = SessionTransferActorResolver.ResolveExplicitActor("actor-jwt", null);

            token.Should().Be("actor-jwt");
            type.Should().Be(Auth0Constants.IdTokenType);
        }

        [Fact]
        public void ResolveExplicitActor_HonorsExplicitType()
        {
            var (token, type) = SessionTransferActorResolver.ResolveExplicitActor("actor-jwt", "urn:acme:actor");

            token.Should().Be("actor-jwt");
            type.Should().Be("urn:acme:actor");
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void ResolveExplicitActor_Throws_InvalidTokenFormat_WhenBlank(string blank)
        {
            var act = () => SessionTransferActorResolver.ResolveExplicitActor(blank, null);

            act.Should().Throw<CustomTokenExchangeException>()
                .Where(e => e.Code == CustomTokenExchangeErrorCode.InvalidTokenFormat);
        }

        [Fact]
        public void ResolveExplicitActor_Throws_WhenBearerPrefixed()
        {
            var act = () => SessionTransferActorResolver.ResolveExplicitActor("Bearer actor-jwt", null);

            act.Should().Throw<CustomTokenExchangeException>()
                .Where(e => e.Code == CustomTokenExchangeErrorCode.InvalidTokenFormat);
        }

        [Fact]
        public void IsIdTokenFresh_ReturnsFalse_ForMalformedToken()
        {
            SessionTransferActorResolver.IsIdTokenFresh("not-a-jwt", System.TimeSpan.Zero).Should().BeFalse();
        }

        [Fact]
        public void IsIdTokenFresh_ReturnsTrue_ForUnexpiredExp()
        {
            var exp = System.DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
            var jwt = JwtWithExp(exp);

            SessionTransferActorResolver.IsIdTokenFresh(jwt, System.TimeSpan.FromMinutes(1)).Should().BeTrue();
        }

        [Fact]
        public void IsIdTokenFresh_ReturnsFalse_WhenExpiredWithinLeeway()
        {
            var exp = System.DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds();
            var jwt = JwtWithExp(exp);

            // 60s leeway means a token expiring in 30s is treated as stale.
            SessionTransferActorResolver.IsIdTokenFresh(jwt, System.TimeSpan.FromSeconds(60)).Should().BeFalse();
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_UsesExplicitActor_AndReturnsStt()
        {
            string capturedBody = string.Empty;
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var result = await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "agent-jwt",
                ActorTokenType = "urn:ietf:params:oauth:token-type:id_token"
            });

            result.SessionTransferToken.Should().Be("the-stt");
            result.IssuedTokenType.Should().Be(Auth0Constants.SessionTransferTokenType);
            result.ExpiresIn.Should().Be(60);
            result.TokenType.Should().Be("N_A");

            capturedBody.Should().Contain("subject_token=customer-token");
            capturedBody.Should().Contain("actor_token=agent-jwt");
            // Audience is built from the configured domain when no resolved domain is set.
            capturedBody.Should().Contain("audience=urn%3Atest.auth0.com%3Asession_transfer");
        }

        // A CTE profile that is not configured for session transfer returns an ordinary access token
        // on this exact path — TokenClient.Send only checks that access_token is non-empty. If the SDK
        // filled in the STT URN itself, that long-lived multi-use token would be handed to
        // BuildSessionTransferRedirect and end up in a query string, and the documented
        // "branch on IssuedTokenType" check would silently pass.
        [Theory]
        // issued_token_type absent entirely
        [InlineData("{\"access_token\":\"a-real-access-token\",\"token_type\":\"Bearer\",\"expires_in\":86400}")]
        // present but an ordinary access token
        [InlineData("{\"access_token\":\"a-real-access-token\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\",\"expires_in\":86400}")]
        // present but empty
        [InlineData("{\"access_token\":\"a-real-access-token\",\"issued_token_type\":\"\",\"token_type\":\"Bearer\",\"expires_in\":86400}")]
        public async Task RequestSessionTransferTokenAsync_Throws_WhenIssuedTokenTypeIsNotStt(string body)
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

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = async () => await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "agent-jwt"
            });

            var ex = (await act.Should().ThrowAsync<CustomTokenExchangeException>()).Which;
            ex.Error.Should().Be("invalid_issued_token_type");
            // The access token must never leak into the exception message — it would land in logs.
            ex.Message.Should().NotContain("a-real-access-token");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_AutoSourcesActor_FromFreshSessionIdToken()
        {
            string capturedBody = string.Empty;
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
                });

            var freshIdToken = IdTokenExpiringIn(10);
            var properties = new AuthenticationProperties();
            properties.Items[".Token.id_token"] = freshIdToken;

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            result.SessionTransferToken.Should().Be("the-stt");
            capturedBody.Should().Contain($"actor_token={Uri.EscapeDataString(freshIdToken)}");
            capturedBody.Should().Contain("actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_RefreshesStaleIdToken_AndPersists()
        {
            var staleIdToken = IdTokenExpiringIn(-5);   // already expired
            var freshIdToken = IdTokenExpiringIn(60);

            // First response = refresh (returns a fresh id_token + access_token); second = STT exchange.
            var responses = new System.Collections.Generic.Queue<HttpResponseMessage>();
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    $"{{\"access_token\":\"new-at\",\"id_token\":\"{freshIdToken}\",\"refresh_token\":\"rotated-rt\",\"expires_in\":86400}}")
            });
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
            });

            var capturedBodies = new System.Collections.Generic.List<string>();
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                    capturedBodies.Add(req.Content!.ReadAsStringAsync().GetAwaiter().GetResult()))
                .ReturnsAsync(() => responses.Dequeue());

            var properties = new AuthenticationProperties();
            properties.Items[".Token.id_token"] = staleIdToken;
            properties.Items[".Token.refresh_token"] = "rt";

            AuthenticationProperties? persisted = null;
            var context = BuildContext(handler.Object, properties, out var authService);
            authService
                .Setup(s => s.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(),
                    It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
                .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>((_, _, _, p) => persisted = p)
                .Returns(Task.CompletedTask);

            var result = await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            result.SessionTransferToken.Should().Be("the-stt");
            // Refresh happened first, then the STT exchange used the fresh id_token as the actor.
            capturedBodies.Should().HaveCount(2);
            capturedBodies[0].Should().Contain("grant_type=refresh_token");
            capturedBodies[1].Should().Contain($"actor_token={Uri.EscapeDataString(freshIdToken)}");
            // The rotated refresh token was persisted (rotation-safe).
            persisted.Should().NotBeNull();
            persisted!.Items[".Token.refresh_token"].Should().Be("rotated-rt");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_ActorRefresh_LeavesPrimaryAccessTokenSlotUntouched()
        {
            var staleIdToken = IdTokenExpiringIn(-5);
            var freshIdToken = IdTokenExpiringIn(60);

            var responses = new System.Collections.Generic.Queue<HttpResponseMessage>();
            // The actor refresh requests no audience/scope, so its access token is for the
            // tenant default — it must never land in the primary slot.
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    $"{{\"access_token\":\"tenant-default-at\",\"id_token\":\"{freshIdToken}\",\"refresh_token\":\"rotated-rt\",\"expires_in\":86400}}")
            });
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
            });

            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => responses.Dequeue());

            var originalExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("o");
            var properties = new AuthenticationProperties();
            properties.Items[".Token.id_token"] = staleIdToken;
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[".Token.access_token"] = "primary-audience-at";
            properties.Items[".Token.expires_at"] = originalExpiresAt;

            var context = BuildContext(handler.Object, properties, out _, audience: "https://api.example.com");

            await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            // The refreshed id_token and the rotated refresh token are persisted...
            properties.Items[".Token.id_token"].Should().Be(freshIdToken);
            properties.Items[".Token.refresh_token"].Should().Be("rotated-rt");
            // ...but the primary access-token slot and its expiry are left exactly as they were.
            // Overwriting them would make GetAccessTokenAsync serve a wrong-audience token from
            // cache, and resetting expires_at would keep it doing so for a full token lifetime.
            properties.Items[".Token.access_token"].Should().Be("primary-audience-at");
            properties.Items[".Token.expires_at"].Should().Be(originalExpiresAt);
        }

        [Fact]
        public async Task GetAccessTokenAsync_AfterSessionTransfer_DoesNotServePoisonedCachedToken()
        {
            var staleIdToken = IdTokenExpiringIn(-5);
            var freshIdToken = IdTokenExpiringIn(60);

            var capturedBodies = new System.Collections.Generic.List<string>();
            var responses = new System.Collections.Generic.Queue<HttpResponseMessage>();
            // 1. actor refresh (no audience/scope)
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    $"{{\"access_token\":\"tenant-default-at\",\"id_token\":\"{freshIdToken}\",\"refresh_token\":\"rotated-rt\",\"expires_in\":86400}}")
            });
            // 2. the STT exchange
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
            });
            // 3. the refresh GetAccessTokenAsync must perform for the app's own audience
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    $"{{\"access_token\":\"correct-audience-at\",\"id_token\":\"{freshIdToken}\",\"expires_in\":3600}}")
            });

            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                    capturedBodies.Add(req.Content!.ReadAsStringAsync().GetAwaiter().GetResult()))
                .ReturnsAsync(() => responses.Dequeue());

            // An already-expired primary access token, as a real session would have when the
            // id_token is stale too.
            var properties = new AuthenticationProperties();
            properties.Items[".Token.id_token"] = staleIdToken;
            properties.Items[".Token.refresh_token"] = "rt";
            properties.Items[".Token.access_token"] = "expired-primary-at";
            properties.Items[".Token.expires_at"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("o");

            var context = BuildContext(handler.Object, properties, out _, audience: "https://api.example.com");

            await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            var accessToken = await context.GetAccessTokenAsync(new AccessTokenRequest());

            // The STT call must not have left a token that looks fresh in the primary slot:
            // GetAccessTokenAsync has to refresh for the configured audience and return that.
            accessToken.Should().Be("correct-audience-at");
            accessToken.Should().NotBe("tenant-default-at");
            capturedBodies.Should().HaveCount(3);
            capturedBodies[2].Should().Contain("audience=https%3A%2F%2Fapi.example.com");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_PersistsRefreshedIdToken_WhenSessionHadNone()
        {
            var freshIdToken = IdTokenExpiringIn(60);

            var responses = new System.Collections.Generic.Queue<HttpResponseMessage>();
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    $"{{\"access_token\":\"at\",\"id_token\":\"{freshIdToken}\",\"refresh_token\":\"rotated-rt\",\"expires_in\":86400}}")
            });
            responses.Enqueue(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(
                    "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
            });

            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(() => responses.Dequeue());

            // No .Token.id_token at all. UpdateTokenValue only writes keys that already exist,
            // so persisting via it would silently no-op and burn a refresh-token rotation per call.
            var properties = new AuthenticationProperties();
            properties.Items[".Token.refresh_token"] = "rt";

            var context = BuildContext(handler.Object, properties, out _);

            var result = await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            result.SessionTransferToken.Should().Be("the-stt");
            properties.Items[".Token.id_token"].Should().Be(freshIdToken);
            properties.Items[".Token.refresh_token"].Should().Be("rotated-rt");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_Throws_ActorUnavailable_WhenNoActorAndNoRefreshToken()
        {
            // Backchannel must never be called on this path.
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage { StatusCode = HttpStatusCode.OK });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = () => context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            (await act.Should().ThrowAsync<CustomTokenExchangeException>())
                .Where(e => e.Code == CustomTokenExchangeErrorCode.ActorUnavailable);

            handler.Protected().Verify("SendAsync", Times.Never(),
                ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>());
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_Throws_InvalidTokenFormat_WhenExplicitActorBlank()
        {
            var handler = SttHandler();
            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = () => context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "   "
            });

            (await act.Should().ThrowAsync<CustomTokenExchangeException>())
                .Where(e => e.Code == CustomTokenExchangeErrorCode.InvalidTokenFormat);
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_Throws_WhenSubjectTokenInvalid()
        {
            var handler = SttHandler();
            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = () => context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "agent-jwt"
            });

            (await act.Should().ThrowAsync<CustomTokenExchangeException>())
                .WithMessage("*subject_token*");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_Surfaces_ServerRejection_Raw()
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
                    StatusCode = HttpStatusCode.BadRequest,
                    Content = new StringContent(
                        "{\"error\":\"invalid_request\",\"error_description\":\"setActor is required when requesting a session transfer token via token exchange.\"}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _);

            var act = () => context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "agent-jwt"
            });

            (await act.Should().ThrowAsync<CustomTokenExchangeException>())
                .Where(e => e.StatusCode == 400
                    && e.Error == "invalid_request"
                    && e.ErrorDescription!.Contains("setActor is required"));
        }

        // A DomainResolver may return a bare host or a full issuer, and Auth0CustomDomainStartupFilter
        // stores whichever it gets verbatim in HttpContext.Items (see
        // Auth0CustomDomainStartupFilterTests, which resolves "https://custom.domain.com"). The
        // audience must carry the bare host for every shape — interpolating the raw value would build
        // urn:https://custom.domain.com:session_transfer, which the token endpoint rejects.
        [Theory]
        [InlineData("tenant.custom.com")]
        [InlineData("https://tenant.custom.com")]
        [InlineData("https://tenant.custom.com/")]
        public async Task RequestSessionTransferTokenAsync_BuildsAudience_FromResolvedDomain_ForMcd(string resolvedDomain)
        {
            string capturedBody = string.Empty;
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent(
                        "{\"access_token\":\"the-stt\",\"issued_token_type\":\"urn:auth0:params:oauth:token-type:session_transfer_token\",\"token_type\":\"N_A\",\"expires_in\":60}")
                });

            var context = BuildContext(handler.Object, new AuthenticationProperties(), out _, resolvedDomain: resolvedDomain);

            await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer",
                ActorToken = "agent-jwt"
            });

            capturedBody.Should().Contain("audience=urn%3Atenant.custom.com%3Asession_transfer");
            // Guard against the scheme leaking into the URN for the issuer-shaped inputs.
            capturedBody.Should().NotContain("https%3A%2F%2Ftenant.custom.com");
        }

        [Fact]
        public async Task RequestSessionTransferTokenAsync_DoesNotPersist_TheStt()
        {
            var handler = SttHandler();
            var properties = new AuthenticationProperties();
            properties.Items[".Token.id_token"] = IdTokenExpiringIn(10);

            var context = BuildContext(handler.Object, properties, out var authService);

            await context.RequestSessionTransferTokenAsync(new SessionTransferTokenRequest
            {
                SubjectToken = "customer-token",
                SubjectTokenType = "urn:acme:customer"
            });

            // No STT written anywhere in the session, and (no refresh needed) no SignInAsync.
            properties.Items.Values.Should().NotContain("the-stt");
            authService.Verify(s => s.SignInAsync(
                It.IsAny<HttpContext>(), It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()), Times.Never());
        }

        private static SessionTransferTokenResult SttResult(string stt = "s t t/value") => new SessionTransferTokenResult
        {
            SessionTransferToken = stt,
            IssuedTokenType = Auth0Constants.SessionTransferTokenType,
            ExpiresIn = 60
        };

        [Fact]
        public void BuildSessionTransferRedirect_AppendsUrlEncodedStt()
        {
            var context = BuildContext(SttHandler().Object, new AuthenticationProperties(), out _);

            var url = context.BuildSessionTransferRedirect("https://target.example.com/login", SttResult("s t t/value"));

            url.Should().Be("https://target.example.com/login?session_transfer_token=s%20t%20t%2Fvalue");
        }

        [Fact]
        public void BuildSessionTransferRedirect_PreservesExistingQuery_AndAppendsOrganization()
        {
            var context = BuildContext(SttHandler().Object, new AuthenticationProperties(), out _);

            var url = context.BuildSessionTransferRedirect(
                "https://target.example.com/login?returnTo=%2Fhome",
                SttResult("stt123"),
                organization: "org_ABC");

            url.Should().Be("https://target.example.com/login?returnTo=%2Fhome&session_transfer_token=stt123&organization=org_ABC");
        }

        [Theory]
        [InlineData("http://target.example.com/login")]   // not https
        [InlineData("/relative/login")]                    // relative
        [InlineData("not a url")]
        public void BuildSessionTransferRedirect_Throws_ForNonAbsoluteHttps(string target)
        {
            var context = BuildContext(SttHandler().Object, new AuthenticationProperties(), out _);

            var act = () => context.BuildSessionTransferRedirect(target, SttResult());

            act.Should().Throw<ArgumentException>();
        }

        // Builds a JWT-shaped string (header.payload.signature) whose payload carries the given exp.
        private static string JwtWithExp(long exp)
        {
            string B64Url(string s)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(s);
                return System.Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
            return $"{B64Url("{\"alg\":\"RS256\"}")}.{B64Url($"{{\"exp\":{exp}}}")}.signature";
        }
    }
}
