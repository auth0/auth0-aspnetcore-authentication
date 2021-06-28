using Microsoft.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Mvc
{
    /// <summary>
    /// Builder class for <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see> when calling logout.
    /// </summary>
    /// <remarks>
    /// Allows for Auth0 specific first-class properties when constructing an instance of <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationproperties">AuthenticationProperties</see>.
    /// </remarks>

    public class LogoutAuthenticationPropertiesBuilder: BaseAuthenticationPropertiesBuilder
    {

        public LogoutAuthenticationPropertiesBuilder(AuthenticationProperties properties = null): base(properties)
        {
                
        }
        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using the provided redirect URI
        /// </summary>
        /// <param name="redirectUri">Full path or absolute URI to be used to redirect back to your application.</param>
        /// <returns>The current <see cref="LogoutAuthenticationPropertiesBuilder"/> instance.</returns>
        /// <remarks>Defaults to "/" when <see cref="WithRedirectUri"/> is not called while building the <see cref="AuthenticationProperties"/>.</remarks>
        public LogoutAuthenticationPropertiesBuilder WithRedirectUri(string redirectUri)
        {
            AuthenticationProperties.RedirectUri = redirectUri;
            return this;
        }

        /// <summary>
        /// Build the <see cref="AuthenticationProperties"/> using a parameter that will be sent to Auth0's logout endpoint.
        /// </summary>
        /// <param name="key">The key for the parameter.</param>
        /// <param name="value">The value for the parameter.</param>
        /// <returns>The current <see cref="LogoutAuthenticationPropertiesBuilder"/> instance.</returns>
        public LogoutAuthenticationPropertiesBuilder WithParameter(string key, string value)
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