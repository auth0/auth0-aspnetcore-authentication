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
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; }
    }
}
