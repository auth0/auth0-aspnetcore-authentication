using Xunit;
using FluentAssertions;
using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class Auth0ServiceCollectionExtensionsTests
    {
        readonly string AUTH0_DOMAIN = "123.auth0.com";
        readonly string AUTH0_CLIENT_ID = "123";
        readonly string AUTH0_CLIENT_SECRET = "456";

        [Fact]
        public async void Should_Have_Redirect_Header()
        {
            await MockHttpContext.Configure(services =>
            {
                services.AddAuth0Mvc(options =>
                {
                    options.Domain = AUTH0_DOMAIN;
                    options.ClientId = AUTH0_CLIENT_ID;
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
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
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);

                redirectUri.Authority.Should().Be("123.auth0.com");
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
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
                });
            }).RunAsync(async context =>
            {
                await context.ChallengeAsync("Auth0", new AuthenticationProperties() { RedirectUri = "/" });

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["client_id"].Should().Be("123");
                queryParameters["scope"].Should().Be("openid profile email");
                queryParameters["redirect_uri"].Should().Be("https://local.auth0.com/callback");
                queryParameters["response_type"].Should().Be("code");
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
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
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
                    options.ClientSecret = AUTH0_CLIENT_SECRET;
                });
            }).RunAsync(async context =>
            {
                var authenticationProperties = new AuthenticationProperties() { RedirectUri = "/" };
                authenticationProperties.Items.Add("scope", "ScopeA ScopeB");

                await context.ChallengeAsync("Auth0", authenticationProperties);

                var redirectUrl = context.Response.Headers[HeaderNames.Location];
                var redirectUri = new Uri(redirectUrl);
                var queryParameters = UriUtils.GetQueryParams(redirectUri);

                queryParameters["scope"].Should().Be("ScopeA ScopeB");
            });
        }
    }
}
