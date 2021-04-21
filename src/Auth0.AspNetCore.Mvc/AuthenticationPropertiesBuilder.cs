using Microsoft.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Builder class for <see cref="AuthenticationProperties"/>.
    /// </summary>
    /// <remarks>
    /// Allows for Auth0 specific first-class properties when constructing an instance of <see cref="AuthenticationProperties"/>.
    /// </remarks>
    public class AuthenticationPropertiesBuilder
    {
        private readonly AuthenticationProperties authenticationProperties;

        public AuthenticationPropertiesBuilder(AuthenticationProperties properties = null)
        {
            authenticationProperties = properties ?? new AuthenticationProperties();
        }

        /// <summary>
        /// Build the AuthenticationProperties using the provided redirect URI
        /// </summary>
        /// <param name="redirectUri">Full path or absolute URI to be used to redirect back to your application.</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithRedirectUri(string redirectUri)
        {
            authenticationProperties.RedirectUri = redirectUri;
            return this;
        }

        /// <summary>
        /// Build the AuthenticationProperties using the provided scope
        /// </summary>
        /// <param name="scope">Scopes to be used to request token(s). (e.g. "Scope1 Scope2 Scope3")</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithScope(string scope)
        {
            authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Scope, scope);
            return this;
        }

        /// <summary>
        /// Build the AuthenticationProperties using the provided audience to request API access.
        /// </summary>
        /// <param name="audience">Audience to request API access for.</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithAudience(string audience)
        {
            authenticationProperties.Items.Add(Auth0AuthenticationParmeters.Audience, audience);
            return this;
        }

        /// <summary>
        /// Build the AuthenticationProperties using the provided organization
        /// </summary>
        /// <param name="organization">The organization used when logging in.</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithOrganization(string organization)
        {
            authenticationProperties.Items.Add("Auth0:organization", organization);
            return this;
        }

        /// <summary>
        /// Build the AuthenticationProperties using the provided invitation
        /// </summary>
        /// <param name="invitation">The Id of an invitation to accept. This is available from the URL that is given when participating in a user invitation flow.</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithInvitation(string invitation)
        {
            authenticationProperties.Items.Add("Auth0:invitation", invitation);
            return this;
        }

        /// <summary>
        /// Build the AuthenticationProperties using an extra parameter
        /// </summary>
        /// <param name="key">The key for the extra parameter.</param>
        /// <param name="value">The value for the extra parameter.</param>
        /// <returns>The current <see cref="AuthenticationPropertiesBuilder"/> instance.</returns>
        public AuthenticationPropertiesBuilder WithExtraParameter(string key, string value)
        {
            authenticationProperties.Items.Add(Auth0AuthenticationParmeters.ExtraParameter(key), value);
            return this;
        }

        /// <summary>
        /// Return the configured <see cref="AuthenticationProperties"/>.
        /// </summary>
        /// <returns>The configured <see cref="AuthenticationProperties"/></returns>
        public AuthenticationProperties Build()
        {
            return authenticationProperties;
        }
    }
}
