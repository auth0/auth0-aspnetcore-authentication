using FluentAssertions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using System.Net.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public class Auth0MiddlewareTests
    {
        public IConfiguration Configuration { get; set; }

        public Auth0MiddlewareTests()
        {
            Configuration = TestConfiguration.GetConfiguration();

        }

        [Fact]
        public async Task Should_Redirect_To_Login_When_Using_Service_Collection_Extensions()
        {
            using (var server = TestServerBuilder.CreateServer(null, false, true))
            {
                using (var client = server.CreateClient())
                {
                    var response = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Protected}"));
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Found);
                    response.Headers.Location.AbsoluteUri.Should().Contain(TestServerBuilder.Login);
                }
            }
        }

        [Fact]
        public async Task Should_Redirect_To_Login()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Protected}"));
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Found);
                    response.Headers.Location.AbsoluteUri.Should().Contain(TestServerBuilder.Login);
                }
            }
        }

        [Fact]
        public async Task Should_Have_Redirect_Header()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);
                    response.Headers.Location.AbsoluteUri.Should().Contain(Configuration["Auth0:Domain"]);
                }
            }
        }

        [Fact]
        public async Task Should_Redirect_To_Authorize_Endpoint()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    redirectUri.Authority.Should().Be(Configuration["Auth0:Domain"]);
                    redirectUri.AbsolutePath.Should().Be("/authorize");
                }
            }
        }

        [Fact]
        public async Task Should_Redirect_Using_Parameters()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["client_id"].Should().Be(Configuration["Auth0:ClientId"]);
                    queryParameters["scope"].Should().Be("openid profile email");
                    queryParameters["redirect_uri"].Should().BeEquivalentTo($"{TestServerBuilder.Host}/{TestServerBuilder.Callback}");
                    queryParameters["response_type"].Should().Be("id_token");
                    queryParameters["response_mode"].Should().Be("form_post");
                }
            }
        }

        [Fact]
        public async Task Should_Allow_Configuring_Scope_When_Calling_ChallengeAsync()
        {
            var scope = "ScopeA ScopeB";
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?scope={scope}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["scope"].Should().Be(scope);
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_CallbackPath()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.CallbackPath = "/Test123";
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["redirect_uri"].Should().Be(string.Format($"{TestServerBuilder.Host}/Test123"));
                }
            }
        }

        [Fact]
        public async void Should_Redirect_To_Logout_Endpoint()
        {
            using (var server = TestServerBuilder.CreateServer(null, true))
            {
                using (var client = server.CreateClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Logout}");
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    redirectUri.Authority.Should().Be(Configuration["Auth0:Domain"]);
                    redirectUri.AbsolutePath.Should().Be("/v2/logout");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_ExtraParameters()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.ExtraParameters = new Dictionary<string, string>() { { "Test", "123" } };
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["Test"].Should().Be("123");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_ExtraParameters_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?extraParameters[0].Key=Test&extraParameters[0].Value=123", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["Test"].Should().Be("123");
                }
            }
        }

        [Fact]
        public async void Should_Override_Global_ExtraParameters_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.ExtraParameters = new Dictionary<string, string>() { { "Test", "123" } };
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?extraParameters[0].Key=Test&extraParameters[0].Value=456", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["Test"].Should().Be("456");
                }
            }
        }

        [Fact]
        public async void Should_Send_Auth0Client_To_Authorize()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);
                    var auth0Client = queryParameters.ContainsKey("auth0Client")
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(queryParameters["auth0Client"]))
                    : null;
                    var auth0ClientJObject = JObject.Parse(auth0Client);

                    auth0Client.Should().NotBeNull();
                    auth0ClientJObject.GetValue("name").Should().NotBeNull();
                    auth0ClientJObject.GetValue("name").ToString().Should().Be("aspnetcore-mvc");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_Organization()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.Organization = "123";
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["organization"].Should().Be("123");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_Organization_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?organization={1}", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}", "123"));
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["organization"].Should().Be("123");
                }
            }
        }

        [Fact]
        public async void Should_Override_Global_Organization_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.Organization = "123";
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?organization={1}", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}", "456"));
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["organization"].Should().Be("456");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_Invitation_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?invitation={1}", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}", "123"));
                    response.StatusCode.Should().Be(System.Net.HttpStatusCode.Redirect);

                    var redirectUri = response.Headers.Location;

                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["invitation"].Should().Be("123");
                }
            }
        }

        [Fact]
        public void Should_Not_Allow_Configuring_Audience_Without_Code()
        {

            Func<TestServer> act = () => TestServerBuilder.CreateServer(options =>
            {
                options.Audience = "http://local.auth0";
            });

            act.Should()
                .Throw<InvalidOperationException>()
                .Which.Message.Should().Be("Using Audience is only supported when using `code` or `code id_token` as the response_type.");
        }

        [Fact]
        public void Should_Not_Allow_Configuring_Audience_Without_ClientSecret()
        {
            Func<TestServer> act = () => TestServerBuilder.CreateServer(options =>
            {
                options.Audience = "http://local.auth0";
                options.ResponseType = OpenIdConnectResponseType.Code;
            });

            act.Should()
                .Throw<ArgumentNullException>()
                .Which.Message.Should().Be("Client Secret can not be null when using `code` or `code id_token` as the response_type. (Parameter 'ClientSecret')");           
        }

        [Fact]
        public async void Should_Allow_Configuring_Audience()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.Audience = "http://local.auth0";
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.ClientSecret = Configuration["Auth0:ClientSecret"];
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}");
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["audience"].Should().Be("http://local.auth0");
                }
            }
        }

        [Fact]
        public async void Should_Allow_Configuring_Audience_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer())
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?audience={1}", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}", "http://local.auth0"));
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["audience"].Should().Be("http://local.auth0");
                }
            }
        }

        [Fact]
        public async void Should_Override_Global_Audience_When_Calling_ChallengeAsync()
        {
            using (var server = TestServerBuilder.CreateServer(options =>
            {
                options.Audience = "http://local.auth0";
                options.ResponseType = "code";
                options.ClientSecret = Configuration["Auth0:ClientSecret"];
            }))
            {
                using (var client = server.CreateClient())
                {
                    var response = await client.GetAsync(string.Format("{0}?audience={1}", $"{TestServerBuilder.Host}/{TestServerBuilder.Login}", "http://remote.auth0"));
                    var redirectUri = response.Headers.Location;
                    var queryParameters = UriUtils.GetQueryParams(redirectUri);

                    queryParameters["audience"].Should().Be("http://remote.auth0");
                }
            }
        }

        [Fact]
        public async Task Should_Send_Auth0Client_To_Token_Endpoint()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, null, nonce), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
             {
                 opt.Backchannel = new HttpClient(mockHandler.Object);
             }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");

                    var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);

                    // Keep track of the nonce as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    // - Include it in the generated ID Token
                    nonce = queryParameters["nonce"];

                    // Keep track of the state as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    var state = queryParameters["state"];

                    var message = new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

                    // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
                    var callbackResponse = (await client.SendAsync(message, setCookie.Value));

                    callbackResponse.Headers.Location.OriginalString.Should().Be("/");
                }
            }

        }

        [Fact]
        public async Task Should_Throw_When_Organization_Provided_But_Claim_Missing()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, null, nonce), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
             {
                 opt.Organization = "org_123";
                 opt.Backchannel = new HttpClient(mockHandler.Object);
             }))
            {
                using (var client = server.CreateClient())
                {

                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");

                    var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);

                    // Keep track of the nonce as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    // - Include it in the generated ID Token
                    nonce = queryParameters["nonce"];

                    // Keep track of the state as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    var state = queryParameters["state"];

                    var message = new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

                    Func<Task> act = async () =>
                    {
                        // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
                        await client.SendAsync(message, setCookie.Value);
                    };

                    var innerException = act
                        .Should()
                        .Throw<Exception>()
                        .And.InnerException;

                    innerException
                        .Should()
                        .BeOfType<Exception>()
                        .Which.Message.Should().Be("Organization claim must be a string present in the ID token.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Organization_Provided_But_Claim_Mismatch()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, "org_456", nonce), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
             {
                 opt.Organization = "org_123";
                 opt.Backchannel = new HttpClient(mockHandler.Object);
             }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");

                    var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);

                    // Keep track of the nonce as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    // - Include it in the generated ID Token
                    nonce = queryParameters["nonce"];

                    // Keep track of the state as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    var state = queryParameters["state"];

                    var message = new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

                    Func<Task> act = async () =>
                    {
                        // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
                        await client.SendAsync(message, setCookie.Value);
                    };

                    var innerException = act
                        .Should()
                        .Throw<Exception>()
                        .And.InnerException;

                    innerException
                        .Should()
                        .BeOfType<Exception>()
                        .Which.Message.Should().Be("Organization claim mismatch in the ID token; expected \"org_123\", found \"org_456\".");
                }
            }
        }

        [Fact]
        public async Task Should_Allow_Custom_Token_Validation()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => JwtUtils.GenerateToken(1, $"https://{domain}/", clientId, null, nonce), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
                opt.Events = new Auth0OptionsEvents
                {
                    OnTokenValidated = (context) =>
                    {
                        context.Fail("Triggered Custom Validation.");
                        return Task.CompletedTask;
                    }
                };
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}"));
                    var setCookie = Assert.Single(loginResponse.Headers, h => h.Key == "Set-Cookie");

                    var queryParameters = UriUtils.GetQueryParams(loginResponse.Headers.Location);

                    // Keep track of the nonce as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    // - Include it in the generated ID Token
                    nonce = queryParameters["nonce"];

                    // Keep track of the state as we need to:
                    // - Send it to the `/oauth/token` endpoint
                    var state = queryParameters["state"];

                    var message = new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

                    Func<Task> act = async () =>
                    {
                        // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
                        await client.SendAsync(message, setCookie.Value);
                    };

                    var innerException = act
                        .Should()
                        .Throw<Exception>()
                        .And.InnerException;

                    innerException
                        .Should()
                        .BeOfType<Exception>()
                        .Which.Message.Should().Be("Triggered Custom Validation.");
                }
            }
        }
    }
}
