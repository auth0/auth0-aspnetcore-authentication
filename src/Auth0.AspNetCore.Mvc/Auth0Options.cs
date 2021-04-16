﻿namespace Auth0.AspNetCore.Mvc
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
        /// Scopes to be used to request token(s).
        /// </summary>
        public string Scope { get; set; } = "openid profile email";
    }
}
