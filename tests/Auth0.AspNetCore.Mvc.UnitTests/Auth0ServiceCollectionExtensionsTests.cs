using Xunit;
using FluentAssertions;
using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Moq;
using System.Threading.Tasks;
using Moq.Protected;
using System.Net.Http;
using System.Threading;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class Auth0ServiceCollectionExtensionsTests
    {
        readonly string AUTH0_DOMAIN = "123.auth0.com";
        readonly string AUTH0_CLIENT_ID = "123";

        [Fact(Skip = "To Implement")]
        public async void Should_Send_Auth0Client_To_Token_Endpoint()
        {
            var mockHandler = TestUtils.SetupOidcMock(JwtUtils.GenerateToken(1, $"https://{AUTH0_DOMAIN}/", AUTH0_CLIENT_ID));
            string nonce = null;

            mockHandler
              .Protected()
              .Setup<Task<HttpResponseMessage>>(
                 "SendAsync",
                 ItExpr.Is<HttpRequestMessage>(me => me.RequestUri.AbsolutePath.Contains("oauth/token")),
                 ItExpr.IsAny<CancellationToken>()
              )
              .ReturnsAsync(() => TestUtils.CreateTokenResponse(JwtUtils.GenerateToken(1, $"https://{AUTH0_DOMAIN}/", AUTH0_CLIENT_ID, null, nonce)))
              .Verifiable();

            var httpClient = new HttpClient(mockHandler.Object)
            {
                BaseAddress = new Uri("http://test.com/"),
            };

            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc((options) =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    // options.Backchannel = httpClient;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                nonce = queryParameters["nonce"];


                try { 
                var handler = context.RequestServices.GetService(typeof(OpenIdConnectHandler)) as OpenIdConnectHandler;

                await handler.InitializeAsync(new AuthenticationScheme(Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

                var result = await handler.HandleRequestAsync();

                mockHandler
                    .Protected()
                    .Verify(
                        "SendAsync",
                        Times.Once(),
                        ItExpr.Is<HttpRequestMessage>(me => me.RequestUri.AbsolutePath.Contains("oauth/token") ),
                        ItExpr.IsAny<CancellationToken>()
                    );
                } catch(Exception e)
                {
                    throw e.InnerException;
                }
            });
        }

        [Fact(Skip = "To Implement")]
        public async void Should_Throw_When_Organization_Provided_But_Claim_Missing()
        {
            var mockHandler = TestUtils.SetupOidcMock(JwtUtils.GenerateToken(1, $"https://{AUTH0_DOMAIN}/", AUTH0_CLIENT_ID));

            // use real http client with mocked handler here
            var httpClient = new HttpClient(mockHandler.Object)
            {
                BaseAddress = new Uri("http://test.com/"),
            };

            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc((options) =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    // options.Backchannel = httpClient;
                    options.Organization = "123";
                });
            }).RunAsync(async context =>
            {

                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithExtraParameter("Test", "123")
                    .Build();

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var handler = context.RequestServices.GetService(typeof(OpenIdConnectHandler)) as OpenIdConnectHandler;

                await handler.InitializeAsync(new AuthenticationScheme(Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

                Func<Task> act = async () => { await handler.HandleRequestAsync(); };

                var innerException = act
                    .Should()
                    .Throw<Exception>()
                    .And.InnerException;

                innerException
                    .Should()
                    .BeOfType<Exception>()
                    .Which.Message.Should().Be("Organization claim must be a string present in the ID token.");
            });
        }

        [Fact(Skip = "To Implement")]
        public async void Should_Throw_When_Organization_Provided_But_Claim_Mismatch()
        {

            var mockHandler = TestUtils.SetupOidcMock(JwtUtils.GenerateToken(1, $"https://{AUTH0_DOMAIN}/", AUTH0_CLIENT_ID, "456"));

            // use real http client with mocked handler here
            var httpClient = new HttpClient(mockHandler.Object)
            {
                BaseAddress = new Uri("http://test.com/"),
            };


            await MockHttpContext.Configure(services =>
            {

                services.AddAuth0Mvc((options) =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    // options.Backchannel = httpClient;
                    options.Organization = "123";
                });
            }).RunAsync(async context =>
            {
                var handler = context.RequestServices.GetService(typeof(OpenIdConnectHandler)) as OpenIdConnectHandler;

                await handler.InitializeAsync(new AuthenticationScheme(Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

                Func<Task> act = async () => { await handler.HandleRequestAsync(); };

                var innerException = act
                    .Should()
                    .Throw<Exception>()
                    .And.InnerException;

                innerException
                    .Should()
                    .BeOfType<Exception>()
                    .Which.Message.Should().Be("Organization claim mismatch in the ID token; expected \"123\", found \"456\".");
            });
        }
    }
}
