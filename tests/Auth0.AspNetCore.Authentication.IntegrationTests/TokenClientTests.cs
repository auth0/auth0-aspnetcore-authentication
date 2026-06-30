using FluentAssertions;
using Moq;
using Moq.Protected;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class TokenClientTests
    {
        [Fact]
        public async Task Returns_Null_When_No_Success_StatusCode()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
              .Protected()
                  .Setup<Task<HttpResponseMessage>>(
                     "SendAsync",
                     ItExpr.IsAny<HttpRequestMessage>(),
                     ItExpr.IsAny<CancellationToken>()
                  )
                  .ReturnsAsync(new HttpResponseMessage()
                  {
                      StatusCode = HttpStatusCode.BadRequest
                  });

           
            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" }, "123");

            result.IsSuccess.Should().BeFalse();
            result.Response.Should().BeNull();
        }

        [Fact]
        public async Task Returns_Failure_With_Error_Details_When_Rejected()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
              .Protected()
                  .Setup<Task<HttpResponseMessage>>(
                     "SendAsync",
                     ItExpr.IsAny<HttpRequestMessage>(),
                     ItExpr.IsAny<CancellationToken>()
                  )
                  .ReturnsAsync(new HttpResponseMessage()
                  {
                      StatusCode = HttpStatusCode.Forbidden,
                      Content = new StringContent("{\"error\":\"invalid_grant\",\"error_description\":\"token revoked\"}")
                  });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" }, "123");

            result.IsSuccess.Should().BeFalse();
            result.StatusCode.Should().Be((int)HttpStatusCode.Forbidden);
            result.Error.Should().Be("invalid_grant");
            result.ErrorDescription.Should().Be("token revoked");
        }

        [Fact]
        public async Task Refresh_WithCustomDomain_UsesCorrectTokenEndpoint()
        {
            var customDomain = "custom.auth0.com";
            var requestedDomain = string.Empty;
            
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.Is<HttpRequestMessage>(req => 
                        req.RequestUri != null &&
                        req.RequestUri.Host == customDomain &&
                        req.RequestUri.AbsolutePath == "/oauth/token"
                    ),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Callback<HttpRequestMessage, CancellationToken>((req, _) => 
                {
                    if (req.RequestUri != null)
                        requestedDomain = req.RequestUri.Host;
                })
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"new_token\",\"token_type\":\"Bearer\",\"expires_in\":86400}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions 
                { 
                    Domain = "default.auth0.com", 
                    ClientId = "cid", 
                    ClientSecret = "secret" 
                }, 
                "refresh_123",
                customDomain  // Pass custom domain
            );

            result.IsSuccess.Should().BeTrue();
            result.Response?.AccessToken.Should().Be("new_token");
            requestedDomain.Should().Be(customDomain);
        }

        [Fact]
        public async Task Refresh_WithoutCustomDomain_UsesDefaultDomain()
        {
            var defaultDomain = "default.auth0.com";
            var requestedDomain = string.Empty;
            
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.Is<HttpRequestMessage>(req => 
                        req.RequestUri != null &&
                        req.RequestUri.Host == defaultDomain &&
                        req.RequestUri.AbsolutePath == "/oauth/token"
                    ),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Callback<HttpRequestMessage, CancellationToken>((req, _) => 
                {
                    if (req.RequestUri != null)
                        requestedDomain = req.RequestUri.Host;
                })
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"new_token\",\"token_type\":\"Bearer\",\"expires_in\":86400}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions 
                { 
                    Domain = defaultDomain, 
                    ClientId = "cid", 
                    ClientSecret = "secret" 
                }, 
                "refresh_123"
                // No custom domain passed, should use default
            );

            result.IsSuccess.Should().BeTrue();
            result.Response?.AccessToken.Should().Be("new_token");
            requestedDomain.Should().Be(defaultDomain);
        }

        [Fact]
        public async Task Refresh_WithAudienceAndScope_IncludesThemInBody()
        {
            var capturedBody = string.Empty;

            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    if (req.Content != null)
                        capturedBody = req.Content.ReadAsStringAsync().Result;
                })
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"new_token\",\"token_type\":\"Bearer\",\"expires_in\":86400,\"scope\":\"read:orders\"}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123",
                null,
                "api://orders",
                "read:orders"
            );

            result.IsSuccess.Should().BeTrue();
            result.Response?.Scope.Should().Be("read:orders");
            capturedBody.Should().Contain("audience=api%3A%2F%2Forders");
            capturedBody.Should().Contain("scope=read%3Aorders");
        }

        [Fact]
        public async Task Refresh_WithoutAudienceAndScope_OmitsThemFromBody()
        {
            var capturedBody = string.Empty;

            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    if (req.Content != null)
                        capturedBody = req.Content.ReadAsStringAsync().Result;
                })
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"new_token\",\"token_type\":\"Bearer\",\"expires_in\":86400}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123"
            );

            capturedBody.Should().NotContain("audience=");
            capturedBody.Should().NotContain("scope=");
        }

        [Fact]
        public async Task Refresh_WithMalformedSuccessBody_ReturnsFailureWithoutThrowing()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{ this is not valid json")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123"
            );

            result.IsSuccess.Should().BeFalse();
            result.Response.Should().BeNull();
            result.StatusCode.Should().Be((int)HttpStatusCode.OK);
            result.Error.Should().Be("invalid_token_response");
            result.ErrorDescription.Should().Be("The token endpoint returned a response that could not be parsed.");
        }

        [Fact]
        public async Task Refresh_WithEmptyJsonObjectBody_ReturnsFailureWithoutThrowing()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123"
            );

            // A 200 with no access_token deserializes to a non-null object whose AccessToken is null;
            // that must be reported as a failure rather than a success carrying an empty token.
            result.IsSuccess.Should().BeFalse();
            result.Response.Should().BeNull();
            result.StatusCode.Should().Be((int)HttpStatusCode.OK);
            result.Error.Should().Be("invalid_token_response");
            result.ErrorDescription.Should().Be("The token endpoint returned a response without an access token.");
        }

        [Fact]
        public async Task Refresh_WithBodyMissingAccessToken_ReturnsFailureWithoutThrowing()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"token_type\":\"Bearer\",\"expires_in\":86400}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123"
            );

            result.IsSuccess.Should().BeFalse();
            result.Response.Should().BeNull();
            result.StatusCode.Should().Be((int)HttpStatusCode.OK);
            result.Error.Should().Be("invalid_token_response");
            result.ErrorDescription.Should().Be("The token endpoint returned a response without an access token.");
        }

        [Fact]
        public async Task Refresh_WithEmptyAccessToken_ReturnsFailureWithoutThrowing()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"\",\"token_type\":\"Bearer\",\"expires_in\":86400}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(
                new Auth0WebAppOptions { Domain = "default.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123"
            );

            result.IsSuccess.Should().BeFalse();
            result.Response.Should().BeNull();
            result.StatusCode.Should().Be((int)HttpStatusCode.OK);
            result.Error.Should().Be("invalid_token_response");
            result.ErrorDescription.Should().Be("The token endpoint returned a response without an access token.");
        }

        [Fact]
        public async Task Refresh_WithNullDomain_ThrowsInvalidOperationException()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            
            var client = new TokenClient(new HttpClient(mockHandler.Object));
            
            Func<Task> act = async () => await client.Refresh(
                new Auth0WebAppOptions 
                { 
                    Domain = null!,  // Null domain
                    ClientId = "cid", 
                    ClientSecret = "secret" 
                }, 
                "refresh_123"
            );

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("Cannot determine domain for token endpoint*");
        }

        [Fact]
        public async Task Refresh_WithEmptyCustomDomain_ThrowsInvalidOperationException()
        {
            var mockHandler = new Mock<HttpMessageHandler>();

            var client = new TokenClient(new HttpClient(mockHandler.Object));

            Func<Task> act = async () => await client.Refresh(
                new Auth0WebAppOptions
                {
                    Domain = "default.auth0.com",
                    ClientId = "cid",
                    ClientSecret = "secret"
                },
                "refresh_123",
                string.Empty  // Empty custom domain
            );

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("Cannot determine domain for token endpoint*");
        }

        [Fact]
        public async Task Returns_Failure_With_MfaToken_When_MfaRequired()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
              .Protected()
                  .Setup<Task<HttpResponseMessage>>(
                     "SendAsync",
                     ItExpr.IsAny<HttpRequestMessage>(),
                     ItExpr.IsAny<CancellationToken>()
                  )
                  .ReturnsAsync(new HttpResponseMessage()
                  {
                      StatusCode = HttpStatusCode.Forbidden,
                      Content = new StringContent("{\"error\":\"mfa_required\",\"error_description\":\"Multifactor authentication required\",\"mfa_token\":\"the-mfa-token\"}")
                  });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.Refresh(new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" }, "123");

            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Be("mfa_required");
            result.MfaToken.Should().Be("the-mfa-token");
        }

        [Fact]
        public async Task Refresh_WhenMfaRequired_ParsesMfaRequirements()
        {
            var body = "{\"error\":\"mfa_required\",\"error_description\":\"Multifactor authentication required\",\"mfa_token\":\"mt\",\"mfa_requirements\":{\"challenge\":[{\"type\":\"otp\"},{\"type\":\"oob\",\"oob_channels\":[\"sms\"]}]}}";
            var handler = new Mock<HttpMessageHandler>();
            handler
                .Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.Forbidden,
                    Content = new StringContent(body)
                });

            var client = new TokenClient(new HttpClient(handler.Object));
            var options = new Auth0WebAppOptions { Domain = "test.auth0.com", ClientId = "cid", ClientSecret = "secret" };

            var result = await client.Refresh(options, "rt", "test.auth0.com");

            result.IsSuccess.Should().BeFalse();
            result.Error.Should().Be("mfa_required");
            result.MfaToken.Should().Be("mt");
            result.MfaRequirements.Should().NotBeNull();
            result.MfaRequirements!.Challenge.Should().HaveCount(2);
            result.MfaRequirements.Challenge![1].OobChannels.Should().ContainSingle().Which.Should().Be("sms");
        }

        [Fact]
        public async Task ExchangeForConnection_Succeeds_AndReturnsToken()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"fc_token\",\"expires_in\":3600,\"scope\":\"email\"}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.ExchangeRefreshTokenForConnectionToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123",
                "google-oauth2");

            result.IsSuccess.Should().BeTrue();
            result.Response!.AccessToken.Should().Be("fc_token");
            result.Response.Scope.Should().Be("email");
        }

        [Fact]
        public async Task ExchangeForConnection_SendsFederatedConnectionGrantParameters()
        {
            string capturedBody = string.Empty;
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"fc_token\",\"expires_in\":3600,\"scope\":\"\"}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            await client.ExchangeRefreshTokenForConnectionToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123",
                "google-oauth2",
                loginHint: "108251234567890123456");

            capturedBody.Should().Contain("grant_type=urn%3Aauth0%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange%3Afederated-connection-access-token");
            capturedBody.Should().Contain("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token");
            capturedBody.Should().Contain("requested_token_type=http%3A%2F%2Fauth0.com%2Foauth%2Ftoken-type%2Ffederated-connection-access-token");
            capturedBody.Should().Contain("subject_token=refresh_123");
            capturedBody.Should().Contain("connection=google-oauth2");
            capturedBody.Should().Contain("login_hint=108251234567890123456");
            // The federated-connection exchange must not send a requested scope — this is
            // what makes the connection cache key scope-independent.
            capturedBody.Should().NotContain("scope=");
        }

        [Fact]
        public async Task ExchangeForConnection_ReturnsFailure_WhenRejected()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.BadRequest,
                    Content = new StringContent("{\"error\":\"invalid_request\",\"error_description\":\"no linked account\"}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.ExchangeRefreshTokenForConnectionToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                "refresh_123",
                "google-oauth2");

            result.IsSuccess.Should().BeFalse();
            result.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
            result.Error.Should().Be("invalid_request");
            result.ErrorDescription.Should().Be("no linked account");
        }

        [Fact]
        public async Task ExchangeCustomToken_SendsExpectedGrantBody()
        {
            string capturedBody = string.Empty;
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"at\",\"expires_in\":3600}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            await client.ExchangeCustomToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                subjectToken: "ext-token",
                subjectTokenType: "urn:acme:legacy-token",
                audience: "https://api.example.com",
                scope: "read:data");

            capturedBody.Should().Contain("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange");
            capturedBody.Should().Contain("client_id=cid");
            capturedBody.Should().Contain("subject_token=ext-token");
            capturedBody.Should().Contain("subject_token_type=urn%3Aacme%3Alegacy-token");
            capturedBody.Should().Contain("audience=https%3A%2F%2Fapi.example.com");
            capturedBody.Should().Contain("scope=read%3Adata");
            // CTE selects the issued token type via the Action/profile, so no requested_token_type.
            capturedBody.Should().NotContain("requested_token_type=");
        }

        [Fact]
        public async Task ExchangeCustomToken_SendsActorTokenPair_AndOrganization()
        {
            string capturedBody = string.Empty;
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"at\",\"expires_in\":3600}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            await client.ExchangeCustomToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                subjectToken: "ext-token",
                subjectTokenType: "urn:acme:legacy-token",
                actorToken: "act-token",
                actorTokenType: "urn:acme:actor-token",
                organization: "org_123");

            capturedBody.Should().Contain("actor_token=act-token");
            capturedBody.Should().Contain("actor_token_type=urn%3Aacme%3Aactor-token");
            capturedBody.Should().Contain("organization=org_123");
        }

        [Fact]
        public async Task ExchangeCustomToken_OmitsOptionalParams_WhenNotProvided()
        {
            string capturedBody = string.Empty;
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .Callback<HttpRequestMessage, CancellationToken>((req, _) =>
                {
                    capturedBody = req.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                })
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("{\"access_token\":\"at\",\"expires_in\":3600}")
                });

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            await client.ExchangeCustomToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                subjectToken: "ext-token",
                subjectTokenType: "urn:acme:legacy-token");

            capturedBody.Should().NotContain("audience=");
            capturedBody.Should().NotContain("scope=");
            capturedBody.Should().NotContain("organization=");
            capturedBody.Should().NotContain("actor_token=");
            capturedBody.Should().NotContain("actor_token_type=");
        }

        [Fact]
        public async Task ExchangeCustomToken_ReturnsFailure_WhenRejected()
        {
            var mockHandler = new Mock<HttpMessageHandler>();
            mockHandler
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

            var client = new TokenClient(new HttpClient(mockHandler.Object));
            var result = await client.ExchangeCustomToken(
                new Auth0WebAppOptions { Domain = "local.auth0.com", ClientId = "cid", ClientSecret = "secret" },
                subjectToken: "ext-token",
                subjectTokenType: "urn:acme:legacy-token");

            result.IsSuccess.Should().BeFalse();
            result.StatusCode.Should().Be((int)HttpStatusCode.Forbidden);
            result.Error.Should().Be("invalid_request");
            result.ErrorDescription.Should().Be("bad profile");
        }
    }
}
