using Moq;
using Moq.Protected;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public class OidcMockBuilder
    {
        private Mock<HttpMessageHandler> _mockHandler = new Mock<HttpMessageHandler>();

        public OidcMockBuilder MockOpenIdConfig()
        {
            _mockHandler
                   .Protected()
                       // Setup the PROTECTED method to mock
                       .Setup<Task<HttpResponseMessage>>(
                          "SendAsync",
                          ItExpr.Is<HttpRequestMessage>(me => me.RequestUri.AbsolutePath.Contains(".well-known/openid-configuration")),
                          //ItExpr.IsAny<HttpRequestMessage>(),
                          ItExpr.IsAny<CancellationToken>()
                       )
                       .ReturnsAsync(ReturnResource("wellknownconfig.json").Result);

            return this;
        }

        public OidcMockBuilder MockJwks()
        {
            _mockHandler
               .Protected()
                   // Setup the PROTECTED method to mock
                   .Setup<Task<HttpResponseMessage>>(
                      "SendAsync",
                      ItExpr.Is<HttpRequestMessage>(me => me.RequestUri.AbsolutePath.Contains(".well-known/jwks.json")),
                      //ItExpr.IsAny<HttpRequestMessage>(),
                      ItExpr.IsAny<CancellationToken>()
                   )
                   .ReturnsAsync(new HttpResponseMessage()
                   {
                       StatusCode = HttpStatusCode.OK,
                       Content = new StringContent("{}"),
                   });

            return this;
        }

        public OidcMockBuilder MockToken(Func<string> idTokenFunc, Func<HttpRequestMessage, bool> matcher = null)
        {
            _mockHandler
              .Protected()
              .Setup<Task<HttpResponseMessage>>(
                 "SendAsync",
                 ItExpr.Is<HttpRequestMessage>(me => me.IsTokenEndPoint() && (matcher == null || matcher(me))),
                 ItExpr.IsAny<CancellationToken>()
              )
              .ReturnsAsync(() => new HttpResponseMessage()
              {
                  StatusCode = HttpStatusCode.OK,
                  Content = new StringContent(@"{
'id_token': '" + idTokenFunc() + @"',
'access_token': '123'
}"),
              })
              .Verifiable();

            return this;
        }

        public Mock<HttpMessageHandler> Build()
        {
            return _mockHandler;
        }

        private async Task<HttpResponseMessage> ReturnResource(string resource)
        {
            var resourceName = "Auth0.AspNetCore.Mvc.IntegrationTests." + resource;
            var names = typeof(Startup).Assembly.GetManifestResourceNames();
            using (var stream = typeof(Startup).Assembly.GetManifestResourceStream(resourceName))
            using (var reader = new StreamReader(stream))
            {
                var body = await reader.ReadToEndAsync();
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                return new HttpResponseMessage()
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = content,
                };
            }
        }
    }
}
