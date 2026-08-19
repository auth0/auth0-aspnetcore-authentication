using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Wraps <see cref="OpenIdConnectOptions.ConfigurationManager"/> with
    /// <see cref="Auth0MtlsConfigurationManager"/> when mTLS is enabled for the scheme. Registered via
    /// <c>TryAddEnumerable</c> after any other post-configure that replaces the configuration manager
    /// (for example multiple custom domains), so it wraps the final manager rather than being
    /// overwritten by it.
    /// </summary>
    internal sealed class MtlsOpenIdConnectPostConfigureOptions : IPostConfigureOptions<OpenIdConnectOptions>
    {
        private readonly IOptionsMonitor<Auth0WebAppOptions> _auth0OptionsMonitor;

        public MtlsOpenIdConnectPostConfigureOptions(IOptionsMonitor<Auth0WebAppOptions> auth0OptionsMonitor)
        {
            _auth0OptionsMonitor = auth0OptionsMonitor;
        }

        public void PostConfigure(string? name, OpenIdConnectOptions options)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            if (!_auth0OptionsMonitor.Get(name).UseMtls)
            {
                return;
            }

            if (options.ConfigurationManager == null)
            {
                return;
            }

            options.ConfigurationManager = new Auth0MtlsConfigurationManager(options.ConfigurationManager);
        }
    }
}
