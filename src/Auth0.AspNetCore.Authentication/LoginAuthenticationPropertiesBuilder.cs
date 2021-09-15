using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Builder class for <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see> when calling login.
    /// </summary>
    /// <remarks>
    /// Allows for Auth0 specific first-class properties when constructing an instance of <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see>.
    /// </remarks>
    public class LoginAuthenticationPropertiesBuilder: BaseAuthenticationPropertiesBuilder
    {

        public LoginAuthenticationPropertiesBuilder(AuthenticationProperties? properties = null): base(properties)
        {
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided redirect URI
        /// </summary>
        /// <param name="redirectUri">Full path or absolute URI to be used to redirect back to your application.</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        /// <remarks>Defaults to "/" when <see cref="WithRedirectUri"/> is not called while building the <see cref="AuthenticationProperties"/>.</remarks>
        public LoginAuthenticationPropertiesBuilder WithRedirectUri(string redirectUri)
        {
            AuthenticationProperties.RedirectUri = redirectUri;
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided scope.
        /// </summary>
        /// <param name="scope">Scopes to be used to request token(s). (e.g. "Scope1 Scope2 Scope3")</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        public LoginAuthenticationPropertiesBuilder WithScope(string scope)
        {
            AuthenticationProperties.Items.Add(Auth0AuthenticationParameters.Scope, scope);
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided audience to request API access.
        /// </summary>
        /// <param name="audience">Audience to request API access for.</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        public LoginAuthenticationPropertiesBuilder WithAudience(string audience)
        {
            AuthenticationProperties.Items.Add(Auth0AuthenticationParameters.Audience, audience);
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided organization
        /// </summary>
        /// <param name="organization">The organization used when logging in.</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        public LoginAuthenticationPropertiesBuilder WithOrganization(string organization)
        {
            AuthenticationProperties.Items.Add(Auth0AuthenticationParameters.Organization, organization);
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided invitation
        /// </summary>
        /// <param name="invitation">The Id of an invitation to accept. This is available from the URL that is given when participating in a user invitation flow.</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        public LoginAuthenticationPropertiesBuilder WithInvitation(string invitation)
        {
            AuthenticationProperties.Items.Add(Auth0AuthenticationParameters.Invitation, invitation);
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using a parameter that will be sent to Auth0's Authorize endpoint.
        /// </summary>
        /// <param name="key">The key for the parameter.</param>
        /// <param name="value">The value for the parameter.</param>
        /// <returns>The current <see cref="LoginAuthenticationPropertiesBuilder"/> instance.</returns>
        public LoginAuthenticationPropertiesBuilder WithParameter(string key, string value)
        {
            AuthenticationProperties.Items.Add(Auth0AuthenticationParameters.Parameter(key), value);
            return this;
        }

        /// <summary>
        /// Return the configured <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see>.
        /// </summary>
        /// <returns>The configured <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see></returns>
        public AuthenticationProperties Build()
        {
            return AuthenticationProperties;
        }
    }
}
