using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Options used to configure the SDK
    /// </summary>
    public class Auth0WebAppOptions
    {
        /// <summary>
        /// The name of the cookie scheme to use
        /// </summary>
        /// <remarks>
        /// The default is <see cref="CookieAuthenticationDefaults.AuthenticationScheme"/>
        /// </remarks>
        public string CookieAuthenticationScheme { get; set; } = CookieAuthenticationDefaults.AuthenticationScheme;

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
        /// Security Key to use with Client Assertion
        /// </summary>
        public SecurityKey? ClientAssertionSecurityKey { get; set; }

        /// <summary>
        /// Algorithm for the Security Key to use with Client Assertion
        /// </summary>
        public string? ClientAssertionSecurityKeyAlgorithm { get; set; }

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
        /// The Organization to which the users should log in to.
        /// </summary>
        /// <remarks>
        /// - If you provide an Organization ID (a string with the prefix `org_`), it will be validated against the `org_id` claim of your user's ID Token. The validation is case-sensitive.
        /// - If you provide an Organization Name (a string *without* the prefix `org_`), it will be validated against the `org_name` claim of your user's ID Token.The validation is case-insensitive.
        /// </remarks>
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
        
        /// <summary>
        /// Gets or sets the optional path the user agent is redirected to if the user
        /// doesn't approve the authorization demand requested by the remote server.
        /// This property is not set by default. In this case, an exception is thrown
        /// if an access_denied response is returned by the remote authorization server.
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

        /// <summary>
        /// Sets whether to use pushed authorization requests or not.
        /// </summary>
        public bool UsePushedAuthorization { get; set; } = false;

        /// <summary>
        /// Gets or sets the authentication scheme corresponding to the middleware
        /// responsible of persisting user's identity after a successful authentication.
        /// This value typically corresponds to a cookie middleware registered in the Startup class.
        /// When omitted, <see cref="P:Microsoft.AspNetCore.Authentication.AuthenticationOptions.DefaultSignInScheme" /> is used as a fallback value.
        /// </summary>
        public string? SignInScheme { get; set; }
        
        /// <summary>
        /// If set, this specifies the target scheme that this scheme should forward SignInAsync calls to.
        /// For example Context.SignInAsync("ThisScheme") =&gt; Context.SignInAsync("ForwardSignInValue");
        /// Set the target to the current scheme to disable forwarding and allow normal processing.
        /// </summary>
        public string? ForwardSignIn { get; set; }
        
        /// <summary>
        /// The Authentication Scheme to use with SignOut on the SignOutPath. SignInScheme will be used if this
        /// is not set.
        /// </summary>
        public string? SignOutScheme { get; set; }
        
        /// <summary>
        /// If set, this specifies the target scheme that this scheme should forward SignOutAsync calls to.
        /// For example Context.SignOutAsync("ThisScheme") =&gt; Context.SignOutAsync("ForwardSignOutValue");
        /// Set the target to the current scheme to disable forwarding and allow normal processing.
        /// </summary>
        public string? ForwardSignOut { get; set; }
        
        /// <summary>
        /// Defines whether access and refresh tokens should be stored in the <see cref="AuthenticationProperties"/> 
        /// after a successful authorization.  This property is set to <c>true</c> by default to
        /// ensure there are no breaking changes with previous versions of the sdk.  Storing tokens will
        /// increase the size of the final authentication cookie.  
        /// </summary>
        public bool SaveTokens { get; set; } = true;
    }
}
