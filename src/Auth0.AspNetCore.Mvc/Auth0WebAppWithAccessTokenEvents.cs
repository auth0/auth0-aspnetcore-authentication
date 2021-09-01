using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
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
    }
}
