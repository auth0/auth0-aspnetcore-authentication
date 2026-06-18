using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using Auth0.AspNetCore.Authentication.Exceptions;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Moq;
using Moq.Protected;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class AuthenticationApiClientTests
    {
        private const string Domain = "test.auth0.com";

        private static readonly IMfaTokenProtector Protector =
            new MfaTokenProtector(new EphemeralDataProtectionProvider());

        private static string Blob(string rawToken, string? audience = null, string? scope = null) =>
            Protector.Protect(new MfaTokenContext
            {
                MfaToken = rawToken,
                Audience = audience,
                Scope = scope,
                ExpiresAtUnix = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
            });

        private static Auth0WebAppOptions Options() =>
            new Auth0WebAppOptions { Domain = Domain, ClientId = "cid", ClientSecret = "secret" };

        // Captures the outgoing request and returns a canned response.
        private static Mock<HttpMessageHandler> Handler(HttpResponseMessage response, Action<HttpRequestMessage, string> capture)
        {
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .Returns<HttpRequestMessage, CancellationToken>(async (req, _) =>
                {
                    var body = req.Content == null ? "" : await req.Content.ReadAsStringAsync();
                    capture(req, body);
                    return response;
                });
            return handler;
        }

        private static HttpResponseMessage Ok(string json) =>
            new HttpResponseMessage { StatusCode = HttpStatusCode.OK, Content = new StringContent(json) };

        private static AuthenticationApiClient Client(Mock<HttpMessageHandler> handler) =>
            new AuthenticationApiClient(new HttpClient(handler.Object), new Uri($"https://{Domain}"), Options(), Protector);

        [Fact]
        public void BaseUri_Returns_ConfiguredUri()
        {
            var client = Client(Handler(Ok("{}"), (_, _) => { }));
            client.BaseUri.Should().Be(new Uri($"https://{Domain}"));
        }

        [Fact]
        public async Task MfaChallengeAsync_Posts_To_MfaChallenge_With_Body()
        {
            HttpRequestMessage? captured = null;
            string capturedBody = "";
            var handler = Handler(Ok("{\"challenge_type\":\"oob\",\"oob_code\":\"oc\"}"),
                (r, b) => { captured = r; capturedBody = b; });
            var client = Client(handler);

            var result = await client.MfaChallengeAsync(new MfaChallengeRequest
            {
                MfaToken = Blob("mt"), ChallengeType = "oob", AuthenticatorId = "auth|1"
            });

            captured!.Method.Should().Be(HttpMethod.Post);
            captured.RequestUri!.AbsoluteUri.Should().Be($"https://{Domain}/mfa/challenge");
            capturedBody.Should().Contain("mfa_token=mt");
            capturedBody.Should().Contain("client_id=cid");
            capturedBody.Should().Contain("client_secret=secret");
            capturedBody.Should().Contain("challenge_type=oob");
            capturedBody.Should().Contain("authenticator_id=auth%7C1");
            result.OobCode.Should().Be("oc");
        }

        [Fact]
        public async Task GetTokenAsync_Otp_Posts_OtpGrant_To_OAuthToken()
        {
            string capturedBody = "";
            HttpRequestMessage? captured = null;
            var handler = Handler(Ok("{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":86400}"),
                (r, b) => { captured = r; capturedBody = b; });
            var client = Client(handler);

            var result = await client.GetTokenAsync(new MfaOtpTokenRequest { MfaToken = Blob("mt"), Otp = "123456" });

            captured!.RequestUri!.AbsoluteUri.Should().Be($"https://{Domain}/oauth/token");
            capturedBody.Should().Contain("grant_type=http%3A%2F%2Fauth0.com%2Foauth%2Fgrant-type%2Fmfa-otp");
            capturedBody.Should().Contain("mfa_token=mt");
            capturedBody.Should().Contain("otp=123456");
            result.AccessToken.Should().Be("at");
            result.ExpiresIn.Should().Be(86400);
        }

        [Fact]
        public async Task GetTokenAsync_Oob_Posts_OobGrant()
        {
            string capturedBody = "";
            var handler = Handler(Ok("{\"access_token\":\"at\",\"expires_in\":3600}"),
                (_, b) => capturedBody = b);
            var client = Client(handler);

            await client.GetTokenAsync(new MfaOobTokenRequest { MfaToken = Blob("mt"), OobCode = "oc", BindingCode = "999" });

            capturedBody.Should().Contain("grant_type=http%3A%2F%2Fauth0.com%2Foauth%2Fgrant-type%2Fmfa-oob");
            capturedBody.Should().Contain("oob_code=oc");
            capturedBody.Should().Contain("binding_code=999");
        }

        [Theory]
        [InlineData("authorization_pending")]
        [InlineData("slow_down")]
        public async Task GetTokenAsync_Oob_Pending_DoesNotThrow_And_PopulatesError(string errorCode)
        {
            // While the user has not yet approved the OOB push/SMS, Auth0 replies HTTP 400 with a
            // pending error. The OOB grant must surface that on the response so callers can poll,
            // not throw.
            var handler = Handler(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.BadRequest,
                Content = new StringContent($"{{\"error\":\"{errorCode}\",\"error_description\":\"still waiting\"}}")
            }, (_, _) => { });
            var client = Client(handler);

            var result = await client.GetTokenAsync(new MfaOobTokenRequest { MfaToken = Blob("mt"), OobCode = "oc" });

            result.Error.Should().Be(errorCode);
            result.ErrorDescription.Should().Be("still waiting");
            result.AccessToken.Should().BeNull();
        }

        [Fact]
        public async Task GetTokenAsync_Oob_Success_PopulatesToken_And_NoError()
        {
            var handler = Handler(Ok("{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600}"),
                (_, _) => { });
            var client = Client(handler);

            var result = await client.GetTokenAsync(new MfaOobTokenRequest { MfaToken = Blob("mt"), OobCode = "oc" });

            result.AccessToken.Should().Be("at");
            result.ExpiresIn.Should().Be(3600);
            result.Error.Should().BeNull();
        }

        [Fact]
        public async Task GetTokenAsync_Oob_GenuineError_Throws_ErrorApiException()
        {
            // A non-pending failure (e.g. invalid_grant) is a real error and must still throw,
            // exactly like the OTP/recovery grants.
            var handler = Handler(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Forbidden,
                Content = new StringContent("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid oob_code.\"}")
            }, (_, _) => { });
            var client = Client(handler);

            var act = async () => await client.GetTokenAsync(new MfaOobTokenRequest { MfaToken = Blob("mt"), OobCode = "oc" });

            var ex = await act.Should().ThrowAsync<ErrorApiException>();
            ex.And.StatusCode.Should().Be(HttpStatusCode.Forbidden);
            ex.And.ApiError!.Error.Should().Be("invalid_grant");
        }

        [Fact]
        public async Task GetTokenAsync_RecoveryCode_Posts_RecoveryGrant()
        {
            string capturedBody = "";
            var handler = Handler(Ok("{\"access_token\":\"at\",\"expires_in\":3600,\"recovery_code\":\"NEW\"}"),
                (_, b) => capturedBody = b);
            var client = Client(handler);

            var result = await client.GetTokenAsync(new MfaRecoveryCodeRequest { MfaToken = Blob("mt"), RecoveryCode = "rc" });

            capturedBody.Should().Contain("grant_type=http%3A%2F%2Fauth0.com%2Foauth%2Fgrant-type%2Fmfa-recovery-code");
            capturedBody.Should().Contain("recovery_code=rc");
            result.RecoveryCode.Should().Be("NEW");
        }

        [Fact]
        public async Task ListMfaAuthenticatorsAsync_Gets_With_BearerHeader()
        {
            HttpRequestMessage? captured = null;
            var handler = Handler(Ok("[{\"id\":\"a1\",\"authenticator_type\":\"otp\",\"active\":true}]"),
                (r, _) => captured = r);
            var client = Client(handler);

            var result = await client.ListMfaAuthenticatorsAsync("the-access-token");

            captured!.Method.Should().Be(HttpMethod.Get);
            captured.RequestUri!.AbsoluteUri.Should().Be($"https://{Domain}/mfa/authenticators");
            captured.Headers.Authorization!.Scheme.Should().Be("Bearer");
            captured.Headers.Authorization.Parameter.Should().Be("the-access-token");
            result.Should().ContainSingle().Which.Id.Should().Be("a1");
        }

        [Fact]
        public async Task AssociateMfaAuthenticatorAsync_Posts_Json_With_BearerHeader()
        {
            HttpRequestMessage? captured = null;
            string capturedBody = "";
            var handler = Handler(Ok("{\"authenticator_type\":\"oob\",\"oob_code\":\"oc\"}"),
                (r, b) => { captured = r; capturedBody = b; });
            var client = Client(handler);

            await client.AssociateMfaAuthenticatorAsync(new AssociateMfaAuthenticatorRequest
            {
                Token = Blob("mt"), AuthenticatorTypes = new[] { "oob" }, OobChannels = new List<string> { "sms" }, PhoneNumber = "+1555"
            });

            captured!.Method.Should().Be(HttpMethod.Post);
            captured.RequestUri!.AbsoluteUri.Should().Be($"https://{Domain}/mfa/associate");
            captured.Headers.Authorization!.Parameter.Should().Be("mt");
            capturedBody.Should().Contain("\"authenticator_types\"");
            capturedBody.Should().Contain("phone_number");
            capturedBody.Should().Contain("1555");
            capturedBody.Should().NotContain("\"Token\""); // [JsonIgnore]
        }

        [Fact]
        public async Task DeleteMfaAuthenticatorAsync_Deletes_With_BearerHeader()
        {
            HttpRequestMessage? captured = null;
            var handler = Handler(new HttpResponseMessage { StatusCode = HttpStatusCode.NoContent },
                (r, _) => captured = r);
            var client = Client(handler);

            await client.DeleteMfaAuthenticatorAsync(new DeleteMfaAuthenticatorRequest
            {
                AccessToken = "at", AuthenticatorId = "auth|1"
            });

            captured!.Method.Should().Be(HttpMethod.Delete);
            captured.RequestUri!.AbsoluteUri.Should().Be($"https://{Domain}/mfa/authenticators/auth%7C1");
            captured.Headers.Authorization!.Parameter.Should().Be("at");
        }

        [Fact]
        public async Task NonSuccess_Throws_ErrorApiException_With_Details()
        {
            var handler = Handler(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Forbidden,
                Content = new StringContent("{\"error\":\"invalid_grant\",\"error_description\":\"Invalid otp_code.\"}")
            }, (_, _) => { });
            var client = Client(handler);

            var act = async () => await client.GetTokenAsync(new MfaOtpTokenRequest { MfaToken = Blob("mt"), Otp = "000000" });

            var ex = await act.Should().ThrowAsync<ErrorApiException>();
            ex.And.StatusCode.Should().Be(HttpStatusCode.Forbidden);
            ex.And.ApiError!.Error.Should().Be("invalid_grant");
            ex.And.ApiError.Message.Should().Be("Invalid otp_code.");
        }

        [Fact]
        public void Dispose_Disposes_HttpClient_When_Owned()
        {
            // When the client owns the HttpClient, Dispose should not throw.
            var client = new AuthenticationApiClient(new HttpClient(), new Uri($"https://{Domain}"), Options(), Protector);
            var act = () => client.Dispose();
            act.Should().NotThrow();
        }

        [Fact]
        public async Task Dispose_DoesNotDispose_HttpClient_When_NotOwned()
        {
            var httpClient = new HttpClient(Handler(Ok("{}"), (_, _) => { }).Object);
            var client = new AuthenticationApiClient(httpClient, new Uri($"https://{Domain}"), Options(), Protector, ownsHttpClient: false);

            client.Dispose();

            // The HttpClient was NOT owned, so it must still be usable after the client is disposed.
            var act = async () => await httpClient.GetAsync($"https://{Domain}/anything");
            await act.Should().NotThrowAsync<ObjectDisposedException>();
        }

        [Fact]
        public async Task MfaChallengeAsync_Unprotects_Blob_RawTokenOnWire()
        {
            string capturedBody = "";
            var handler = Handler(Ok("{\"challenge_type\":\"oob\",\"oob_code\":\"oc\"}"),
                (_, b) => { capturedBody = b; });
            var client = Client(handler);

            await client.MfaChallengeAsync(new MfaChallengeRequest { MfaToken = Blob("raw-mt") });

            capturedBody.Should().Contain("mfa_token=raw-mt");
            capturedBody.Should().NotContain("CfDJ"); // Data Protection blobs start with this prefix
        }

        [Fact]
        public async Task GetTokenAsync_Otp_Unprotects_Blob_And_Sends_BoundAudienceScope()
        {
            string capturedBody = "";
            var handler = Handler(Ok("{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":3600}"),
                (_, b) => { capturedBody = b; });
            var client = Client(handler);

            await client.GetTokenAsync(new MfaOtpTokenRequest
            {
                MfaToken = Blob("raw-mt", "https://api.example.com", "read:items"),
                Otp = "123456"
            });

            capturedBody.Should().Contain("mfa_token=raw-mt");
            capturedBody.Should().Contain("otp=123456");
            capturedBody.Should().Contain("audience=https%3A%2F%2Fapi.example.com");
            capturedBody.Should().Contain("scope=read%3Aitems");
        }

        [Fact]
        public async Task GetTokenAsync_Otp_Garbage_Blob_Throws_Invalid_BeforeHttp()
        {
            var called = false;
            var handler = Handler(Ok("{}"), (_, _) => { called = true; });
            var client = Client(handler);

            Func<Task> act = () => client.GetTokenAsync(new MfaOtpTokenRequest { MfaToken = "garbage", Otp = "1" });

            await act.Should().ThrowAsync<MfaTokenInvalidException>();
            called.Should().BeFalse();
        }

        [Fact]
        public async Task AssociateMfaAuthenticatorAsync_WithBlob_SendsRawTokenAsBearer()
        {
            HttpRequestMessage? captured = null;
            var handler = Handler(Ok("{\"authenticator_type\":\"otp\",\"secret\":\"s\"}"),
                (r, _) => { captured = r; });
            var client = Client(handler);

            await client.AssociateMfaAuthenticatorAsync(new AssociateMfaAuthenticatorRequest
            {
                Token = Blob("raw-mt"),
                AuthenticatorTypes = new[] { "otp" }
            });

            captured!.Headers.Authorization!.Parameter.Should().Be("raw-mt");
        }

        [Fact]
        public async Task AssociateMfaAuthenticatorAsync_WithAccessToken_SendsItAsIs()
        {
            HttpRequestMessage? captured = null;
            var handler = Handler(Ok("{\"authenticator_type\":\"otp\",\"secret\":\"s\"}"),
                (r, _) => { captured = r; });
            var client = Client(handler);

            await client.AssociateMfaAuthenticatorAsync(new AssociateMfaAuthenticatorRequest
            {
                Token = "plain-access-token",
                AuthenticatorTypes = new[] { "otp" }
            });

            captured!.Headers.Authorization!.Parameter.Should().Be("plain-access-token");
        }
    }

    public class WithAuthenticationApiClientRegistrationTests
    {
        [Fact]
        public void WithAuthenticationApiClient_Registers_Resolvable_Client()
        {
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            Microsoft.Extensions.DependencyInjection.DataProtectionServiceCollectionExtensions.AddDataProtection(services);
            var options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "cid", ClientSecret = "secret" };
            var builder = new Auth0WebAppAuthenticationBuilder(services, options);

            builder.WithAuthenticationApiClient();

            var provider = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services);
            var client = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
                .GetService<Auth0.AspNetCore.Authentication.AuthenticationApi.IAuthenticationApiClient>(provider);

            client.Should().NotBeNull();
            client!.BaseUri.Should().Be(new Uri("https://test.auth0.com"));
        }

        [Fact]
        public void WithAccessToken_Registers_MfaTokenProtector_WithoutAuthenticationApiClient()
        {
            // GetAccessTokenAsync resolves IMfaTokenProtector on the mfa_required path. Because MRRT
            // refresh is supported without WithAuthenticationApiClient(), the base WithAccessToken
            // path must register the protector too — otherwise mfa_required surfaces as an opaque DI
            // failure instead of the typed MfaRequiredException.
            var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
            Microsoft.Extensions.DependencyInjection.DataProtectionServiceCollectionExtensions.AddDataProtection(services);
            var options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "cid", ClientSecret = "secret" };
            var builder = new Auth0WebAppAuthenticationBuilder(services, options);

            builder.WithAccessToken(o => o.UseRefreshTokens = true);

            var provider = Microsoft.Extensions.DependencyInjection.ServiceCollectionContainerBuilderExtensions.BuildServiceProvider(services);
            var protector = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
                .GetService<IMfaTokenProtector>(provider);

            protector.Should().NotBeNull();
        }
    }
}
