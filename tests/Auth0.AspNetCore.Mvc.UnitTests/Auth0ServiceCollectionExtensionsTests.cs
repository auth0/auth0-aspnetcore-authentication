using Xunit;
using FluentAssertions;
using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;
using System.Text;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Moq;
using System.Threading.Tasks;
using Moq.Protected;
using System.Net.Http;
using System.Threading;
using System.Collections.Generic;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class Auth0ServiceCollectionExtensionsTests
    {
        readonly string AUTH0_DOMAIN = "123.auth0.com";
        readonly string AUTH0_CLIENT_ID = "123";
        readonly string AUTH0_CLIENT_SECRET = "123";

        [Fact]
        public async void Should_Have_Redirect_Header()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                context.Response.StatusCode.Should().Be(302);
                context.Response.Headers[HeaderNames.Location].Should().NotBeNullOrEmpty();
            });
        }

        [Fact]
        public async void Should_Redirect_To_Authorize_Endpoint()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);

                redirectUri.Authority.Should().Be(AUTH0_DOMAIN);
                redirectUri.AbsolutePath.Should().Be("/authorize");
            });
        }

        [Fact]
        public async void Should_Redirect_Using_Parameters()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["client_id"].Should().Be(AUTH0_CLIENT_ID);
                queryParameters["scope"].Should().Be("openid profile email");
                queryParameters["redirect_uri"].Should().Be("https://local.auth0.com/callback");
                queryParameters["response_type"].Should().Be("id_token");
                queryParameters["response_mode"].Should().Be("form_post");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Scope()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Scope = "ScopeA ScopeB";
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["scope"].Should().Be("ScopeA ScopeB");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Scope_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Scope, "ScopeA ScopeB");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["scope"].Should().Be("ScopeA ScopeB");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Scope_When_Calling_ChallengeAsync_Using_Builder()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithScope("ScopeA ScopeB")
                    .Build();

                await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["scope"].Should().Be("ScopeA ScopeB");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_CallbackPath()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;

                    options.CallbackPath = "/Test123";
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["redirect_uri"].Should().Be("https://local.auth0.com/Test123");
            });
        }

        [Fact]
        public async void Should_Redirect_To_Logout_Endpoint()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                await context.SignOutAsync(Auth0Constants.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);

                redirectUri.Authority.Should().Be(AUTH0_DOMAIN);
                redirectUri.AbsolutePath.Should().Be("/v2/logout");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_ExtraParameters()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.ExtraParameters = new Dictionary<string, string>() { { "Test", "123" } };
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["Test"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_ExtraParameters_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.ExtraParameter("Test"), "123");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["Test"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Override_Global_ExtraParameters_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.ExtraParameters = new Dictionary<string, string>() { { "Test", "123" } };
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };

                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.ExtraParameter("Test"), "456");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["Test"].Should().Be("456");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_ExtraParameters_When_Calling_ChallengeAsync_Using_Builder()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithExtraParameter("Test", "123")
                    .Build();

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["Test"].Should().Be("123");
            });
        }


        [Fact]
        public async void Should_Send_Auth0Client_To_Authorize()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Scope = "ScopeA ScopeB";
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);
                var auth0Client = queryParameters.ContainsKey("auth0Client")
                    ? Encoding.UTF8.GetString(Convert.FromBase64String(queryParameters["auth0Client"]))
                    : null;
                var auth0ClientJObject = JObject.Parse(auth0Client);

                auth0Client.Should().NotBeNull();
                auth0ClientJObject.GetValue("name").Should().NotBeNull();
                auth0ClientJObject.GetValue("name").ToString().Should().Be("aspnetcore-mvc");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Organization()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Organization = "123";
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["organization"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Organization_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Organization, "123");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["organization"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Override_Global_Organization_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Organization = "123";
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };

                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Organization, "456");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["organization"].Should().Be("456");
            });
        }

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

                await handler.InitializeAsync(new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

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

        [Fact]
        public async void Should_Not_Allow_Configuring_Audience_Without_Code()
        {
            await MockHttpContext.Configure(services =>
            {
                Func<AuthenticationBuilder> act = () => services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Audience = "http://local.auth0";
                });

                act.Should()
                    .Throw<InvalidOperationException>()
                    .Which.Message.Should().Be("Using Audience is only supported when using `code` or `code id_token` as the response_type.");
            }).RunAsync(async context => {});
        }

        [Fact]
        public async void Should_Not_Allow_Configuring_Audience_Without_ClientSecret()
        {
            await MockHttpContext.Configure(services =>
            {
                Func<AuthenticationBuilder> act = () => services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.Audience = "http://local.auth0";
                    options.ResponseType = OpenIdConnectResponseType.Code;
                });

                act.Should()
                    .Throw<ArgumentNullException>()
                    .Which.Message.Should().Be("Client Secret can not be null when using `code` or `code id_token` as the response_type. (Parameter 'ClientSecret')");
            }).RunAsync(async context => { });
        }

        [Fact]
        public async void Should_Allow_Configuring_Audience()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
                    options.Audience = "http://local.auth0";
                    options.ResponseType = OpenIdConnectResponseType.Code;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["audience"].Should().Be("http://local.auth0");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Audience_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Audience, "http://local.auth0");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["audience"].Should().Be("http://local.auth0");
            });
        }

        [Fact]
        public async void Should_Override_Global_Audience_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
                    options.Audience = "http://local.auth0";
                    options.ResponseType = OpenIdConnectResponseType.Code;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };

                authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Audience, "http://remote.auth0");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["audience"].Should().Be("http://remote.auth0");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Audience_When_Calling_ChallengeAsync_Using_Builder()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithExtraParameter("Test", "123")
                    .WithAudience("http://local.auth0")
                    .Build();

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["audience"].Should().Be("http://local.auth0");
            });
        }
        [Fact]
        public async void Should_Allow_Configuring_Organization_When_Calling_ChallengeAsync_Using_Builder()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithOrganization("123")
                    .Build();

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["organization"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Invitation_When_Calling_ChallengeAsync()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add("Auth0:invitation", "123");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["invitation"].Should().Be("123");
            });
        }

        [Fact]
        public async void Should_Allow_Configuring_Invitation_When_Calling_ChallengeAsync_Using_Builder()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .WithInvitation("123")
                    .Build();

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["invitation"].Should().Be("123");
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

                await handler.InitializeAsync(new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

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

                await handler.InitializeAsync(new AuthenticationScheme(Auth0Constants.AuthenticationScheme, null, typeof(OpenIdConnectHandler)), context);

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
