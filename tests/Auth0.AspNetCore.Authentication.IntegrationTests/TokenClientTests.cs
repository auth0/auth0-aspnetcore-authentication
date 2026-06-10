using FluentAssertions;
using Moq;
using Moq.Protected;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

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

            result.Should().BeNull();
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

            result.Should().NotBeNull();
            result?.AccessToken.Should().Be("new_token");
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

            result.Should().NotBeNull();
            result?.AccessToken.Should().Be("new_token");
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

            result.Should().NotBeNull();
            result?.Scope.Should().Be("read:orders");
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
    }
}
