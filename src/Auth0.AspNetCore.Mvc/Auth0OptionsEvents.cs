using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Events allowing you to hook into specific moments in the Auth0 middleware.
    /// </summary>
    public class Auth0OptionsEvents
    {
        /// <summary>
        /// Executed when an Access Token is missing while it was expected, allowing you to react accordingly.
        /// </summary>
        /// <example>
        /// <code>
        /// services.AddAuth0Mvc(options =>
        /// {
        ///     options.Events = new Auth0OptionsEvents
        ///     {
        ///         OnMissingAccessToken = async (context) =>
        ///         {
        ///             await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ///             var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
        ///             await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        ///         }
        ///     };
        /// });
        /// </code>
        /// </example>
        public Func<HttpContext, Task> OnMissingAccessToken { get; set; }

        /// <summary>
        /// Executed when a Refresh Token is missing while it was expected, allowing you to react accordingly.
        /// </summary>
        /// <example>
        /// <code>
        /// services.AddAuth0Mvc(options =>
        /// {
        ///     options.Events = new Auth0OptionsEvents
        ///     {
        ///         OnMissingRefreshToken = async (context) =>
        ///         {
        ///             await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ///             var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
        ///             await context.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        ///         }
        ///     };
        /// });
        /// </code>
        /// </example>
        public Func<HttpContext, Task> OnMissingRefreshToken { get; set; }
    }
}
