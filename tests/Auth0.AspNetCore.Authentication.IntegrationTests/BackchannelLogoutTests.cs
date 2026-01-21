using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.Exceptions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Builders;
using Auth0.AspNetCore.Authentication.IntegrationTests.Extensions;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.IntegrationTests.Utils;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests;

public class BackchannelLogoutTests
{
    [Fact]
    public async Task Should_Return_405_If_Not_Post()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var res = await client.SendAsync($"{TestServerBuilder.Host}/backchannel-logout");

        res.StatusCode.Should().Be((HttpStatusCode)405);
    }

    [Fact]
    public async Task Should_return_400_when_not_form_urlencoded()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var message = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        var response = await client.SendAsync(message);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Be("Only application/x-www-form-urlencoded is allowed.");
    }

    [Fact]
    public async Task Should_return_400_when_no_logout_token()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var formData = new Dictionary<string, string> { { "Foo", "Bar" } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Be("Missing logout_token.");
    }

    [Fact]
    public async Task Should_Validate_Signature_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .SignWithRs256("Auth0.AspNetCore.Authentication.IntegrationTests.jwks2.json")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Signature validation failed.");
    }

    [Fact]
    public async Task Should_Validate_Issuer_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://bad_issuer/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();
        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Issuer validation failed.");
    }

    [Fact]
    public async Task Should_Validate_Audience_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience("bad_audience")
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Audience validation failed.");
    }

    [Fact]
    public async Task Should_Validate_Sid_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);

        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Session Id (sid) claim must be a string present in the logout token.");
    }

    [Fact]
    public async Task Should_Validate_Nonce_On_Backchannel_Logout()
    {
        var nonce = "test";
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .WithClaim(JwtRegisteredClaimNames.Nonce, nonce)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Nonce, nonce)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Nonce (nonce) claim must not be present in the logout token.");
    }

    [Fact]
    public async Task Should_Validate_Events_When_Missing_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should().Contain("Events (events) claim must be present in the logout token.");
    }

    [Fact]
    public async Task Should_Validate_Events_When_Missing_Property_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"foo\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var content = await response.Content.ReadAsStringAsync();
        var error = ApiError.Parse(content);

        response.StatusCode.Should().Be((HttpStatusCode)400);
        error.Message.Should()
            .Contain(
                "Events (events) claim must contain a 'http://schemas.openid.net/event/backchannel-logout' property in the logout token.");
    }

    [Fact]
    public async Task Should_Pass_Validation_On_Backchannel_Logout()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        response.StatusCode.Should().Be((HttpStatusCode)200);
    }

    [Fact]
    public async Task Should_Logout_And_Clear_Cookie()
    {
        var nonce = "";
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
                // ReSharper disable once AccessToModifiedClosure
                .WithClaim(JwtRegisteredClaimNames.Nonce, nonce)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, true, false, null, true);
        using var client = server.CreateClient();
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

        var message = new HttpRequestMessage(HttpMethod.Get,
            $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

        // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
        var callbackResponse = (await client.SendAsync(message, setCookie.Value));
        var callbackCookies = callbackResponse.Headers.GetValues("Set-Cookie").ToList();

        var protectedMessage =
            new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Protected}");
        var protectedResponse = await client.SendAsync(protectedMessage, callbackCookies);

        // Accessing a protected endpoint before logging out should be OK.
        protectedResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        protectedResponse.Headers.Location.Should().BeNull();

        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var protectedMessage2 =
            new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Protected}");
        var protectedResponse2 = await client.SendAsync(protectedMessage2, callbackCookies);

        // Accessing a protected endpoint after logging out should redirect.
        protectedResponse2.StatusCode.Should().Be(HttpStatusCode.Found);
        protectedResponse2.Headers.Location.Should().NotBeNull();
        protectedResponse2.Headers.Location!.AbsoluteUri.Should().Contain(TestServerBuilder.Login);
    }

    [Fact]
    public async Task Should_Not_Logout_When_Sid_Doesnt_Match()
    {
        var nonce = "";
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                // ReSharper disable once AccessToModifiedClosure
                .WithClaim(JwtRegisteredClaimNames.Nonce, nonce)
                .WithClaim(JwtRegisteredClaimNames.Sid, "sid2")
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, true, false, null, true);
        using var client = server.CreateClient();
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

        var message = new HttpRequestMessage(HttpMethod.Get,
            $"{TestServerBuilder.Host}/{TestServerBuilder.Callback}?state={state}&nonce={nonce}&code=123");

        // Pass along the Set-Cookies to ensure `Nonce` and `Correlation` cookies are set.
        var callbackResponse = (await client.SendAsync(message, setCookie.Value));
        var callbackCookies = callbackResponse.Headers.GetValues("Set-Cookie").ToList();

        var protectedMessage =
            new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Protected}");
        var protectedResponse = await client.SendAsync(protectedMessage, callbackCookies);

        // Accessing a protected endpoint before logging out should be OK.
        protectedResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        protectedResponse.Headers.Location.Should().BeNull();

        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        var protectedMessage2 =
            new HttpRequestMessage(HttpMethod.Get, $"{TestServerBuilder.Host}/{TestServerBuilder.Protected}");
        var protectedResponse2 = await client.SendAsync(protectedMessage2, callbackCookies);

        // Accessing a protected endpoint after logging out should be still be OK when the SID didn't match.
        protectedResponse2.StatusCode.Should().Be(HttpStatusCode.OK);
        protectedResponse2.Headers.Location.Should().BeNull();
    }

    [Fact]
    public async Task Should_Support_Custom_Authentication_Scheme()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain = configuration["Auth0:Domain"];
        var clientId = configuration["Auth0:ClientId"];
        var customScheme = "CustomScheme";

        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        // Create a server with a custom authentication scheme
        using var server = TestServerBuilder.CreateServerWithCustomScheme(customScheme,
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();

        // Create a valid logout token
        var logoutToken = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData = new Dictionary<string, string> { { "logout_token", logoutToken } };
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req.Content = new FormUrlEncodedContent(formData);
        using var response = await client.SendAsync(req);

        response.StatusCode.Should().Be((HttpStatusCode)200);
    }

    [Fact]
    public async Task Should_Reject_Tokens_From_Different_Issuers_Multiple_Custom_Domains()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain1 = "tenant1.auth0.com";
        var domain2 = "tenant2.auth0.com";
        var clientId = configuration["Auth0:ClientId"];

        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain1}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(
            opt => { opt.Backchannel = new HttpClient(mockHandler.Object); }, null, false, false, false, null, true);
        using var client = server.CreateClient();

        // Test logout token from domain1
        var logoutToken1 = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain1}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid1")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData1 = new Dictionary<string, string> { { "logout_token", logoutToken1 } };
        using var req1 = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req1.Content = new FormUrlEncodedContent(formData1);
        using var response1 = await client.SendAsync(req1);

        // Should fail because issuer doesn't match the configured domain
        response1.StatusCode.Should().Be((HttpStatusCode)400);
        var content1 = await response1.Content.ReadAsStringAsync();
        var error1 = ApiError.Parse(content1);
        error1.Message.Should().Contain("Issuer validation failed");

        // Test logout token from domain2
        var logoutToken2 = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain2}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid2")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData2 = new Dictionary<string, string> { { "logout_token", logoutToken2 } };
        using var req2 = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req2.Content = new FormUrlEncodedContent(formData2);
        using var response2 = await client.SendAsync(req2);

        // Should also fail because issuer doesn't match the configured domain
        response2.StatusCode.Should().Be((HttpStatusCode)400);
        var content2 = await response2.Content.ReadAsStringAsync();
        var error2 = ApiError.Parse(content2);
        error2.Message.Should().Contain("Issuer validation failed");
    }

    [Fact]
    public async Task Should_Support_Backchannel_Logout_With_Multiple_Custom_Domains()
    {
        var configuration = TestConfiguration.GetConfiguration();
        var domain1 = "tenant1.auth0.com";
        var domain2 = "tenant2.auth0.com";
        var clientId = configuration["Auth0:ClientId"];

        var mockHandler = new OidcMockBuilder()
            .MockOpenIdConfig()
            .MockJwks()
            .MockToken(() => new JwtTokenBuilder(1)
                .WithIssuer($"https://{domain1}/")
                .WithAudience(clientId)
                .Build())
            .Build();

        using var server = TestServerBuilder.CreateServer(opt =>
        {
            opt.Domain = domain1;
            opt.Backchannel = new HttpClient(mockHandler.Object);
        }, null, false, false, false, null, true);
        using var client = server.CreateClient();

        // Test logout token from domain1 - should succeed
        var logoutToken1 = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain1}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid1")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData1 = new Dictionary<string, string> { { "logout_token", logoutToken1 } };
        using var req1 = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req1.Content = new FormUrlEncodedContent(formData1);
        using var response1 = await client.SendAsync(req1);

        // Should succeed because issuer matches the configured domain
        response1.StatusCode.Should().Be((HttpStatusCode)200);

        // Test logout token from domain2 - should fail
        var logoutToken2 = new JwtTokenBuilder(1)
            .WithIssuer($"https://{domain2}/")
            .WithAudience(clientId)
            .WithClaim(JwtRegisteredClaimNames.Sid, "sid2")
            .WithClaim("events", "{ \"http://schemas.openid.net/event/backchannel-logout\": {} }")
            .Build();

        var formData2 = new Dictionary<string, string> { { "logout_token", logoutToken2 } };
        using var req2 = new HttpRequestMessage(HttpMethod.Post, $"{TestServerBuilder.Host}/backchannel-logout");
        req2.Content = new FormUrlEncodedContent(formData2);
        using var response2 = await client.SendAsync(req2);

        // Should fail because issuer doesn't match the configured domain
        response2.StatusCode.Should().Be((HttpStatusCode)400);
        var content2 = await response2.Content.ReadAsStringAsync();
        var error2 = ApiError.Parse(content2);
        error2.Message.Should().Contain("Issuer validation failed");
    }
}