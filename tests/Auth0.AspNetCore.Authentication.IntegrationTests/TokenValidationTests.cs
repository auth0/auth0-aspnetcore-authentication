using FluentAssertions;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using System.Net.Http;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.IntegrationTests.Utils;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class TokenValidationTests
    {
        public IConfiguration Configuration { get; set; }

        public TokenValidationTests()
        {
            Configuration = TestConfiguration.GetConfiguration();

        }

        [Fact]
        public async Task Should_Throw_When_Missing_Issuer()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, null, clientId, nonce, "1"), (me) => me.HasAuth0ClientHeader())
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
                        .BeOfType<SecurityTokenInvalidIssuerException>();
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Invalid_Issuer()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://invalid/", clientId, nonce, "1"), (me) => me.HasAuth0ClientHeader())
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
                        .BeOfType<SecurityTokenInvalidIssuerException>();
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Missing_Subject()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, null), (me) => me.HasAuth0ClientHeader())
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
                        .Which.Message.Should().Be("Subject (sub) claim must be a string present in the ID token.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Missing_Audience()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", null, nonce, "1"), (me) => me.HasAuth0ClientHeader())
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
                        .BeOfType<SecurityTokenInvalidAudienceException>();
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Invalid_Audience()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", "invalid", nonce, "1"), (me) => me.HasAuth0ClientHeader())
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
                        .BeOfType<SecurityTokenInvalidAudienceException>();
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Expired()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", null, true), (me) => me.HasAuth0ClientHeader())
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
                        .BeOfType<SecurityTokenExpiredException>();
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Missing_Azp_And_Multiple_Audiences()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", null, false, "789"), (me) => me.HasAuth0ClientHeader())
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
                        .Which.Message.Should().Be("Authorized Party (azp) claim must be a string present in the ID token when Audiences (aud) claim has multiple values.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Invalid_Azp_And_Multiple_Audiences()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", null, false, "789", "789"), (me) => me.HasAuth0ClientHeader())
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
                        .Which.Message.Should().Be("Authorized Party (azp) claim mismatch in the ID token; expected \"123\", found \"789\".");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Max_Age_Exists_And_Auth_Time_Does_Not()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", null), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.MaxAge = TimeSpan.FromDays(2);
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
                        .Which.Message.Should().Be("Authentication Time (auth_time) claim must be an integer present in the ID token when MaxAge specified.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Max_Age_Exists_And_Auth_Time_Is_Invalid()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", null, false, null, null, DateTime.UtcNow.Subtract(TimeSpan.FromHours(3))), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.MaxAge = TimeSpan.FromHours(2);
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
                        .Which.Message.Should().StartWith("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication.");
                }
            }
        }

        [Fact]
        public void Should_Throw_When_Missing_Iat()
        {
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, "1"),
                new Claim(JwtRegisteredClaimNames.Sub, "1")
            };

            var token = new JwtSecurityToken($"https://{domain}/", clientId, claims, null, null);

            Action act = () =>
            {
                // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
                IdTokenValidator.Validate(new Auth0WebAppOptions(), token);
            };

            var innerException = act
                .Should()
                .Throw<IdTokenValidationException>()
                .Which.Message.Should().Be("Issued At (iat) claim must be an integer present in the ID token.");


        }

        [Fact]
        public async Task Should_Throw_When_Missing_OrgId()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "organizationA"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=org_123"));
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
                        .Which.Message.Should().Be("Organization claim (org_id) must be a string present in the ID token.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_OrgId_Mismatch()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "org_abc"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=org_123"));
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
                        .Which.Message.Should().Be($"Organization claim (org_id) mismatch in the ID token; expected \"org_123\", found \"org_abc\".");
                }
            }
        }

        [Fact]
        public async Task Should_Not_Throw_When_OrgId_Match()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "org_123"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=org_123"));
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

                    await client.SendAsync(message, setCookie.Value);
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_Missing_OrgName()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "org_123"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=organizationA"));
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
                        .Which.Message.Should().Be("Organization claim (org_name) must be a string present in the ID token.");
                }
            }
        }

        [Fact]
        public async Task Should_Throw_When_OrgName_Mismatch()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "organizationb"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=organizationa"));
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
                        .Which.Message.Should().Be($"Organization claim (org_name) mismatch in the ID token; expected \"organizationa\", found \"organizationb\".");
                }
            }
        }

        [Fact]
        public async Task Should_Not_Throw_When_OrgName_Match()
        {
            var nonce = "";
            var configuration = TestConfiguration.GetConfiguration();
            var domain = configuration["Auth0:Domain"];
            var clientId = configuration["Auth0:ClientId"];
            var mockHandler = new OidcMockBuilder()
                .MockOpenIdConfig()
                .MockJwks()
                .MockToken(() => GenerateToken(1, $"https://{domain}/", clientId, nonce, "1", "organizationa"), (me) => me.HasAuth0ClientHeader())
                .Build();

            using (var server = TestServerBuilder.CreateServer(opt =>
            {
                opt.Backchannel = new HttpClient(mockHandler.Object);
            }))
            {
                using (var client = server.CreateClient())
                {
                    var loginResponse = (await client.SendAsync($"{TestServerBuilder.Host}/{TestServerBuilder.Login}?organization=organizationA"));
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

                    await client.SendAsync(message, setCookie.Value);
                }
            }
        }

        private string GenerateToken(int userId, string issuer, string audience, string nonce, string subject, string organization = null, bool expired = false, string extraAudience = null, string azp = null, DateTime? authTime = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            };

            if (subject != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Sub, subject));
            }

            if (extraAudience != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, extraAudience));
            }

            if (!string.IsNullOrWhiteSpace(organization))
            {
                var organizationClaim = organization.StartsWith("org_") ? "org_id" : "org_name";
                claims.Add(new Claim(organizationClaim, organization));
            }

            if (!string.IsNullOrWhiteSpace(nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }

            if (!string.IsNullOrWhiteSpace(azp))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Azp, azp));
            }

            if (authTime != null)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.AuthTime, EpochTime.GetIntDate(authTime.Value).ToString()));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                NotBefore = expired ? DateTime.UtcNow.Subtract(new TimeSpan(0, 2, 0, 0)) : (DateTime?) null,
                Expires = expired ? DateTime.UtcNow.Subtract(new TimeSpan(0, 1, 0, 0)) : DateTime.UtcNow.AddDays(7),
                Issuer = issuer,
                Audience = audience,
                IssuedAt = null
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }



    }
}
