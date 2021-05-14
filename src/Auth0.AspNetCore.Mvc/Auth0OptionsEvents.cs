using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Events allowing you to hook into specific moments in the OpenID Connect pipeline.
    /// </summary>
    public class Auth0OptionsEvents
    {
        /// <summary>
        /// Executed when the ID Token has been validated internally,
        /// allowing you to implement any additional validation.
        /// </summary>
        /// <example>
        /// <code>
        /// services.AddAuth0Mvc(options =>
        /// {
        ///     options.Events = new Auth0OptionsEvents
        ///     {
        ///         OnTokenValidated = context =>
        ///         {
        ///             var someClaimValue = context.SecurityToken.Claims.SingleOrDefault(claim => claim.Type == "claim_name")?.Value;
        /// 
        ///             if (string.IsNullOrWhiteSpace(someClaimValue))
        ///             {
        ///                 context.Fail("Custom claim must be a string present in the ID token.");
        ///             }
        ///             
        ///             return Task.CompletedTask;
        ///         }
        ///     };
        /// });
        /// </code>
        /// </example>
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; }
    }
}
