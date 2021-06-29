using FluentAssertions;
using Moq;
using Moq.Protected;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public class TokenClientTests
    {
        [Fact]
        public async Task Disposes_HttpClient_it_creates_on_dispose()
        {
            var client = new TokenClient();
            client.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.Refresh(new Auth0WebAppOptions { Domain = "local.auth0.com" }, ""));
        }

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
            var result = await client.Refresh(new Auth0WebAppOptions { Domain = "local.auth0.com" }, "123");

            result.Should().BeNull();
        }
    }
}
