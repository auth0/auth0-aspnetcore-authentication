﻿using System.Collections.Generic;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Options used to configure the SDK
    /// </summary>
    public class Auth0Options
    {
        /// <summary>
        /// Auth0 domain name, e.g. tenant.auth0.com.
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// Client ID of the application.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Client secret of the application.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// The audience to be used for requesting API access.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Scopes to be used to request token(s). (e.g. "Scope1 Scope2 Scope3")
        /// </summary>
        public string Scope { get; set; } = "openid profile email";

        /// <summary>
        /// The path within the application to redirect the user to.
        /// </summary>
        /// <remarks>Processed internally by the Open Id Co nnect middleware.</remarks> 
        public string CallbackPath { get; set; }

        /// <summary>
        /// Extra parameters to be send to `/authorize`.
        /// </summary>
        /// <example>
        /// services.AddAuth0Mvc(options =>
        /// {
        ///     options.ExtraParameters = new Dictionary<string, string>() { {"Test", "123" } };
        /// });
        /// </example>
        public IDictionary<string, string> ExtraParameters { get; set; } = new Dictionary<string, string>();
    }
}
