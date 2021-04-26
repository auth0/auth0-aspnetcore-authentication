using Moq;
using Moq.Protected;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class TestUtils
    {
        #region Dummy data
        public static string OIDC_CONFIG = @"{
  ""issuer"": ""https://tenant.eu.auth0.com/"",
  ""authorization_endpoint"": ""https://tenant.eu.auth0.com/authorize"",
  ""token_endpoint"": ""https://tenant.eu.auth0.com/oauth/token"",
  ""device_authorization_endpoint"": ""https://tenant.eu.auth0.com/oauth/device/code"",
  ""userinfo_endpoint"": ""https://tenant.eu.auth0.com/userinfo"",
  ""mfa_challenge_endpoint"": ""https://tenant.eu.auth0.com/mfa/challenge"",
  ""jwks_uri"": ""https://tenant.eu.auth0.com/.well-known/jwks.json"",
  ""registration_endpoint"": ""https://tenant.eu.auth0.com/oidc/register"",
  ""revocation_endpoint"": ""https://tenant.eu.auth0.com/oauth/revoke"",
  ""scopes_supported"": [
    ""openid"",
    ""profile"",
    ""offline_access"",
    ""name"",
    ""given_name"",
    ""family_name"",
    ""nickname"",
    ""email"",
    ""email_verified"",
    ""picture"",
    ""created_at"",
    ""identities"",
    ""phone"",
    ""address""
  ],
  ""response_types_supported"": [
    ""code"",
    ""token"",
    ""id_token"",
    ""code token"",
    ""code id_token"",
    ""token id_token"",
    ""code token id_token""
  ],
  ""code_challenge_methods_supported"": [""S256"", ""plain""],
  ""response_modes_supported"": [""query"", ""fragment"", ""form_post""],
  ""subject_types_supported"": [""public""],
  ""id_token_signing_alg_values_supported"": [""HS256"", ""RS256""],
  ""token_endpoint_auth_methods_supported"": [
    ""client_secret_basic"",
    ""client_secret_post""
  ],
  ""claims_supported"": [
    ""aud"",
    ""auth_time"",
    ""created_at"",
    ""email"",
    ""email_verified"",
    ""exp"",
    ""family_name"",
    ""given_name"",
    ""iat"",
    ""identities"",
    ""iss"",
    ""name"",
    ""nickname"",
    ""phone_number"",
    ""picture"",
    ""sub""
  ],
  ""request_uri_parameter_supported"": ""false""
}
";
        #endregion

        public static HttpResponseMessage CreateTokenResponse(string idToken)
        {
            return new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(@"{
'id_token': '" + idToken + @"',
'access_token': '123'
}"),
            };
        }

        public static Mock<HttpMessageHandler> SetupOidcMock(string idToken)
        {
            var mockHandler = new Mock<HttpMessageHandler>();


            mockHandler
               .Protected()
                   // Setup the PROTECTED method to mock
                   .Setup<Task<HttpResponseMessage>>(
                      "SendAsync",
                      ItExpr.Is<HttpRequestMessage>(me => me.RequestUri.AbsolutePath.Contains(".well-known/openid-configuration")),
                      //ItExpr.IsAny<HttpRequestMessage>(),
                      ItExpr.IsAny<CancellationToken>()
                   )
                   .ReturnsAsync(new HttpResponseMessage()
                   {
                       StatusCode = HttpStatusCode.OK,
                       Content = new StringContent(OIDC_CONFIG),
                   });

            mockHandler
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

            return mockHandler;
        }
    }
}
