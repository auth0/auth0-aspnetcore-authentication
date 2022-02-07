using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Options used to configure the SDK
    /// </summary>
    public class Auth0WebAppOptions
    {
        /// <summary>
        /// Auth0 domain name, e.g. tenant.auth0.com.
        /// </summary>
        public string Domain { get; set; } = null!;

        /// <summary>
        /// Client ID of the application.
        /// </summary>
        public string ClientId { get; set; } = null!;

        /// <summary>
        /// Client Secret of the application.
        /// </summary>
        /// <remarks>
        /// Required when using <see cref="ResponseType"/> set to `code` or `code id_token`.
        /// </remarks>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// Scopes to be used to request token(s). (e.g. "Scope1 Scope2 Scope3")
        /// </summary>
        public string Scope { get; set; } = "openid profile";

        /// <summary>
        /// The path within the application to redirect the user to.
        /// </summary>
        /// <remarks>Processed internally by the Open Id Connect middleware.</remarks> 
        public string? CallbackPath { get; set; }

        /// <summary>
        /// Whether or not to skip adding the Cookie Middleware.
        /// </summary>
        /// <remarks>Defaults to false.</remarks> 
        public bool SkipCookieMiddleware { get; set; } = false;

        /// <summary>
        /// The Id of the organization to which the users should log in to.
        /// </summary>
        public string? Organization { get; set; }

        /// <summary>
        /// Parameters to be send to Auth0's `/authorize` endpoint.
        /// </summary>
        /// <example>
        /// services.AddAuth0WebAppAuthentication(options =>
        /// {
        ///     options.LoginParameters = new Dictionary{string, string}() { {"Test", "123" } };
        /// });
        /// </example>
        public IDictionary<string, string>? LoginParameters { get; set; } = new Dictionary<string, string>();

        /// <summary>
        /// Events allowing you to hook into specific moments in the OpenID Connect pipeline.
        /// </summary>
        public OpenIdConnectEvents? OpenIdConnectEvents { get; set; }

        /// <summary>
        /// Set the ResponseType to be used.
        /// </summary>
        /// <remarks>
        /// Supports `id_token`, `code` or `code id_token`, defaults to `id_token` when omitted.
        /// </remarks>
        public string? ResponseType { get; set; }

        /// <summary>
        /// Backchannel used to communicate with the Identity Provider.
        /// </summary>
        public HttpClient? Backchannel { get; set; }

        /// <summary>
        /// If provided, will set the 'max_age' parameter with the authentication request.
        /// If the identity provider has not actively authenticated the user within the length of time specified, 
        /// the user will be prompted to re-authenticate.
        /// </summary>
        public TimeSpan? MaxAge { get; set; }
    }
}
