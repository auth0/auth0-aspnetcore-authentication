using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Moq;
using Moq.Protected;
using Newtonsoft.Json;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Builders
{
    /// <summary>
    /// Builder used to set up a Mock{HttpMessageHandler} that handles the Oidc and OAuth requests.
    /// </summary>
    public class OidcMockBuilder
    {
        private readonly Mock<HttpMessageHandler> _mockHandler = new Mock<HttpMessageHandler>();

        /// <summary>
        /// Mock the `.well-known/openid-configuration` request.
        /// </summary>
        /// <returns>The contents of `wellknownconfig.json`, containing some dummy information needed for the tests.</returns>
        public OidcMockBuilder MockOpenIdConfig(string configFile = "wellknownconfig.json")
        {
            _mockHandler
                   .Protected()
                       .Setup<Task<HttpResponseMessage>>(
                          "SendAsync",
                          ItExpr.Is<HttpRequestMessage>(me => me.IsOpenIdConfigurationEndPoint()),
                          ItExpr.IsAny<CancellationToken>()
                       )
                       .ReturnsAsync(ReturnResource(configFile).Result);

            return this;
        }

        /// <summary>
        /// Mock the `.well-known/jwks.json` request.
        /// </summary>
        /// <returns>An empty object as the contents are irrelevant for the tests.</returns>
        public OidcMockBuilder MockJwks()
        {
            _mockHandler
               .Protected()
                   .Setup<Task<HttpResponseMessage>>(
                      "SendAsync",
                      ItExpr.Is<HttpRequestMessage>(me => me.IsJwksEndPoint()),
                      ItExpr.IsAny<CancellationToken>()
                   )
                   .ReturnsAsync(ReturnResource("jwks.json").Result);

            return this;
        }

        /// <summary>
        /// Mock the `oauth/token` request.
        /// </summary>
        /// <param name="idTokenFunc">Func that, when called, returns the ID Token to be used in thhe response.</param>
        /// <param name="matcher">Custom matcher Func to only match specific requests.</param>
        /// <returns></returns>
        public OidcMockBuilder MockToken(Func<string> idTokenFunc, Func<HttpRequestMessage, bool> matcher = null, int expiresIn = 70, bool includeAccessToken = true, HttpStatusCode statusCode = HttpStatusCode.OK, string refreshToken = "456")
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
                  StatusCode = statusCode,
                  Content = new StringContent(BuildTokenResponse(idTokenFunc(), expiresIn, includeAccessToken, refreshToken)),
              })
              .Verifiable();

            return this;
        }
        
        /// <summary>
        /// Mock the `oauth/par` request.
        /// </summary>
        /// <param name="requestUri">Value to set for the request_uri property on the PAR response.</param>
        /// <param name="matcher">Custom matcher Func to only match specific requests.</param>
        /// <returns></returns>
        public OidcMockBuilder MockPAR(string requestUri, Func<HttpRequestMessage, bool> matcher = null, int expiresIn = 70, HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            _mockHandler
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.Is<HttpRequestMessage>(me => me.IsPAREndPoint() && (matcher == null || matcher(me))),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(() => new HttpResponseMessage()
                {
                    StatusCode = statusCode,
                    Content = new StringContent(statusCode == HttpStatusCode.OK ? BuildPARResponse(requestUri, expiresIn) : BuildPARError()),
                })
                .Verifiable();

            return this;
        }

        public Mock<HttpMessageHandler> Build()
        {
            return _mockHandler;
        }

        /// <summary>
        /// Converts an Embedded Resource to an HttpResponseMessage.
        /// </summary>
        /// <param name="resource">The name of the resource, has to exist as `Auth0.AspNetCore.Authentication.IntegrationTests.{resource}`</param>
        /// <returns>The HttpResponseMessage instance containing the Embedded Resource.</returns>
        private async Task<HttpResponseMessage> ReturnResource(string resource)
        {
            var resourceName = "Auth0.AspNetCore.Authentication.IntegrationTests." + resource;
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

        private string BuildTokenResponse(string idToken, int expiresIn, bool includeAccessToken, string refreshToken)
        {
            var tokenContents = new Dictionary<string, object>
            {
                ["id_token"] = idToken,
                ["expires_in"] = expiresIn
            };
            if (includeAccessToken)
            {
                tokenContents["access_token"] = "123";
            }
            if (!string.IsNullOrEmpty(refreshToken))
            {
                tokenContents["refresh_token"] = refreshToken;
            }
            var token = JsonConvert.SerializeObject(tokenContents);
            return token;
        }
        
        private string BuildPARResponse(string requestUri, int expiresIn)
        {
            var tokenContents = new Dictionary<string, object>
            {
                ["request_uri"] = requestUri,
                ["expires_in"] = expiresIn
            };
            
            return JsonConvert.SerializeObject(tokenContents);
        }
        
        private string BuildPARError()
        {
            var error = new Dictionary<string, object>
            {
                ["error"] = "Test_Error",
                ["error_description"] = "Test Error"
            };
            
            return JsonConvert.SerializeObject(error);
        }
    }
}

