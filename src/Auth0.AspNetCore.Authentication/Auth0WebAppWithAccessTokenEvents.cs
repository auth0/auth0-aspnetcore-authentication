using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Events allowing you to hook into specific moments in the Auth0 middleware.
    /// </summary>
    public class Auth0WebAppWithAccessTokenEvents
    {
        /// <summary>
        /// Executed when an Access Token is missing where one was expected, allowing you to react accordingly.
        /// </summary>
        /// <example>
        /// <code>
        /// services
        ///   .AddAuth0WebAppAuthentication(options => {})
        ///   .WithAccessToken(options =>
        ///   {
        ///       options.Events = new Auth0WebAppWithAccessTokenEvents
        ///       {
        ///           OnMissingAccessToken = async (context) =>
        ///           {
        ///               await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ///               var authenticationProperties = new AuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
        ///               await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        ///           }
        ///       };
        ///   });
        /// </code>
        /// </example>
        public Func<HttpContext, Task>? OnMissingAccessToken { get; set; }

        /// <summary>
        /// Executed when a Refresh Token is missing where one was expected, allowing you to react accordingly.
        /// </summary>
        /// <example>
        /// <code>
        /// services
        ///   .AddAuth0WebAppAuthentication(options => {})
        ///   .WithAccessToken(options =>
        ///   {
        ///       options.Events = new Auth0WebAppWithAccessTokenEvents
        ///       {
        ///           OnMissingRefreshToken = async (context) =>
        ///           {
        ///               await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ///               var authenticationProperties = new AuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
        ///               await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        ///           }
        ///       };
        ///   });
        /// </code>
        /// </example>
        public Func<HttpContext, Task>? OnMissingRefreshToken { get; set; }

        /// <summary>
        /// Executed when an attempt to exchange the refresh token for an access token failed,
        /// allowing you to react accordingly (e.g. force a re-login). This fires when a refresh
        /// token was present but the token endpoint rejected the request (such as an
        /// <c>invalid_grant</c> for a revoked or expired refresh token) or could not be reached.
        /// The supplied <see cref="AccessTokenRefreshFailedContext"/> carries the failure details
        /// (status code, <c>error</c>/<c>error_description</c>, or the thrown exception) so you can
        /// distinguish a terminal failure from a transient one.
        /// </summary>
        /// <example>
        /// <code>
        /// services
        ///   .AddAuth0WebAppAuthentication(options => {})
        ///   .WithAccessToken(options =>
        ///   {
        ///       options.Events = new Auth0WebAppWithAccessTokenEvents
        ///       {
        ///           OnAccessTokenRefreshFailed = async (context) =>
        ///           {
        ///               // A revoked or expired refresh token is terminal — force a re-login.
        ///               if (context.Error == "invalid_grant")
        ///               {
        ///                   await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ///                   var authenticationProperties = new AuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
        ///                   await context.HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        ///               }
        ///           }
        ///       };
        ///   });
        /// </code>
        /// </example>
        public Func<AccessTokenRefreshFailedContext, Task>? OnAccessTokenRefreshFailed { get; set; }
    }
}
