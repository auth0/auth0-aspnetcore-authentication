using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.BackchannelLogout;
using Auth0.AspNetCore.Authentication.CustomDomains;
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Auth0.AspNetCore.Authentication.Mtls;
using System.Net.Http;
using Microsoft.AspNetCore.Hosting;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Builder to add functionality on top of OpenId Connect authentication. 
    /// </summary>
    public class Auth0WebAppAuthenticationBuilder
    {
        private readonly IServiceCollection _services;
        private readonly Auth0WebAppOptions _options;
        private readonly string _authenticationScheme;
        private bool _accessTokenConfigured;

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services, Auth0WebAppOptions options) : this(services, Auth0Constants.AuthenticationScheme, options)
        {
        }

        /// <summary>
        /// Constructs an instance of <see cref="Auth0WebAppAuthenticationBuilder"/>
        /// </summary>
        /// <param name="services">The original <see href="https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.iservicecollection">IServiceCollection</see> instance</param>
        /// <param name="authenticationScheme">The authentication scheme to use.</param>
        /// <param name="options">The <see cref="Auth0WebAppOptions"/> used when calling AddAuth0WebAppAuthentication.</param>
        public Auth0WebAppAuthenticationBuilder(IServiceCollection services, string authenticationScheme, Auth0WebAppOptions options)
        {
            _services = services;
            _options = options;
            _authenticationScheme = authenticationScheme;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0WebAppWithAccessTokenOptions"/></param>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            EnableWithAccessToken(configureOptions);
            return this;
        }

        /// <summary>
        /// Configures the use of Access Tokens
        /// </summary>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithBackchannelLogout()
        {
            _services.AddTransient<BackchannelLogoutHandler>(sp =>
                new BackchannelLogoutHandler(
                    sp.GetRequiredService<ILogoutTokenHandler>(),
                    _authenticationScheme));
            _services.AddTransient<ILogoutTokenHandler, DefaultLogoutTokenHandler>();
            return this;
        }

        /// <summary>
        /// Registers an <see cref="IAuthenticationApiClient"/> for calling Auth0 Authentication API
        /// MFA endpoints (for example, to recover from an <c>mfa_required</c> error). The client
        /// authenticates using the <see cref="Auth0WebAppOptions.ClientId"/> and client credentials
        /// configured on the SDK.
        /// </summary>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/>.</returns>
        public Auth0WebAppAuthenticationBuilder WithAuthenticationApiClient()
        {
            _services.AddHttpClient();
            _services.TryAddSingleton<IMfaTokenProtector>(sp =>
                new MfaTokenProtector(sp.GetRequiredService<IDataProtectionProvider>()));
            _services.AddTransient<IAuthenticationApiClient>(sp =>
            {
                var backchannel = _options.Backchannel;
                var httpClient = backchannel ?? sp.GetRequiredService<IHttpClientFactory>().CreateClient();
                return new AuthenticationApiClient(
                    httpClient,
                    new Uri($"https://{_options.Domain}"),
                    _options,
                    sp.GetRequiredService<IMfaTokenProtector>(),
                    ownsHttpClient: backchannel == null,
                    mtlsEndpointResolver: sp.GetService<Mtls.Auth0MtlsEndpointResolver>());
            });
            return this;
        }

        /// <summary>
        /// Configures support for multiple Auth0 custom domains with dynamic domain resolution.
        /// </summary>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0CustomDomainsOptions"/></param>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithCustomDomains(Action<Auth0CustomDomainsOptions> configureOptions)
        {
            EnableCustomDomains(configureOptions);
            return this;
        }

        /// <summary>
        /// Configures Mutual TLS (mTLS) client authentication. The supplied
        /// <see cref="Auth0MtlsOptions.HttpClient"/> — which must carry the client certificate — is used
        /// as the backchannel for every client-authenticated request, and requests are routed through
        /// the tenant's <c>mtls_endpoint_aliases</c>.
        /// </summary>
        /// <remarks>
        /// Must be called <b>before</b> <see cref="WithAccessToken"/> and (when combined) <b>after</b>
        /// <see cref="WithCustomDomains"/>. The certificate is the sole credential: do not also set
        /// <see cref="Auth0WebAppOptions.ClientSecret"/>, <see cref="Auth0WebAppOptions.ClientAssertionSecurityKey"/>,
        /// or <see cref="Auth0WebAppOptions.Backchannel"/>.
        /// </remarks>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0MtlsOptions"/>.</param>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/>.</returns>
        public Auth0WebAppAuthenticationBuilder WithMtls(Action<Auth0MtlsOptions> configureOptions)
        {
            var mtlsOptions = new Auth0MtlsOptions();
            configureOptions(mtlsOptions);

            if (mtlsOptions.HttpClient == null)
            {
                throw new InvalidOperationException(
                    "WithMtls requires an HttpClient configured with the client certificate.");
            }

            if (_accessTokenConfigured)
            {
                throw new InvalidOperationException("WithMtls must be called before WithAccessToken.");
            }

            if (_options.Backchannel != null)
            {
                throw new InvalidOperationException(
                    "Backchannel cannot be set when WithMtls supplies an HttpClient. Configure a single HttpClient " +
                    "with both the client certificate and your transport settings, and pass it to WithMtls.");
            }

            if (!string.IsNullOrWhiteSpace(_options.ClientSecret) || _options.ClientAssertionSecurityKey != null)
            {
                throw new InvalidOperationException(
                    "mTLS cannot be combined with a client secret or client assertion; the certificate is the sole credential.");
            }

            // Dual-write to both option instances: the builder instance drives oidcOptions.Backchannel
            // (code exchange + PAR) via the ConfigureOpenIdConnect closure, and the DI-registered
            // named instance is what the HttpContextExtensions call sites read via IOptionsSnapshot.
            _options.Backchannel = mtlsOptions.HttpClient;
            _options.UseMtls = true;
            _services.Configure<Auth0WebAppOptions>(_authenticationScheme, o =>
            {
                o.Backchannel = mtlsOptions.HttpClient;
                o.UseMtls = true;
            });

            _services.AddHttpClient();
            _services.TryAddSingleton<Auth0MtlsEndpointResolver>();
            _services.TryAddSingleton<MtlsCnfInspector>();

            // Register last so, with WithCustomDomains registered first, this post-configure runs after
            // the custom-domains one and wraps its ConfigurationManager rather than being overwritten.
            _services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, MtlsOpenIdConnectPostConfigureOptions>());

            return this;
        }

        /// <summary>
        /// Stores the authentication session server-side using the supplied
        /// <see href="https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.iticketstore">ITicketStore</see>,
        /// keeping only a session key in the cookie. <typeparamref name="TStore"/> is resolved
        /// from the service provider, so it may depend on other registered services
        /// (e.g. <see href="https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.caching.distributed.idistributedcache">IDistributedCache</see>).
        /// </summary>
        /// <typeparam name="TStore">The <c>ITicketStore</c> implementation to use.</typeparam>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithSessionStore<TStore>() where TStore : class, ITicketStore
        {
            // Register and resolve the concrete type rather than ITicketStore: this avoids a
            // pre-registered ITicketStore silently shadowing TStore, and lets schemes using
            // different store types each get their own registration.
            _services.TryAddSingleton<TStore>();
            EnableSessionStore(sp => sp.GetRequiredService<TStore>());
            return this;
        }

        /// <summary>
        /// Stores the authentication session server-side using the supplied
        /// <see href="https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.iticketstore">ITicketStore</see>
        /// instance, keeping only a session key in the cookie.
        /// </summary>
        /// <param name="ticketStore">The <c>ITicketStore</c> instance to use.</param>
        /// <returns>An instance of <see cref="Auth0WebAppAuthenticationBuilder"/></returns>
        public Auth0WebAppAuthenticationBuilder WithSessionStore(ITicketStore ticketStore)
        {
            if (ticketStore == null)
            {
                throw new ArgumentNullException(nameof(ticketStore));
            }

            EnableSessionStore(_ => ticketStore);
            return this;
        }

        private void EnableSessionStore(Func<IServiceProvider, ITicketStore> resolveStore)
        {
            // Attach the store to the cookie handler on the SDK's own cookie scheme. Resolving
            // the scheme here is what frees callers from having to name it correctly themselves
            // (a mismatch would otherwise leave the store silently unused).
            var cookieScheme = _options.CookieAuthenticationScheme;

            _services
                .AddOptions<CookieAuthenticationOptions>(cookieScheme)
                .Configure<IServiceProvider>((cookieOptions, sp) =>
                    cookieOptions.SessionStore = resolveStore(sp));
        }

        private void EnableCustomDomains(Action<Auth0CustomDomainsOptions> configureOptions)
        {
            var customDomainsOptions = new Auth0CustomDomainsOptions();
            configureOptions(customDomainsOptions);
            
            // Validate that DomainResolver is configured
            if (customDomainsOptions.DomainResolver == null)
            {
                throw new InvalidOperationException(
                    $"DomainResolver must be configured when using {nameof(WithCustomDomains)}. " +
                    $"Set the {nameof(Auth0CustomDomainsOptions.DomainResolver)} property to provide a function that resolves the Auth0 domain for each request.");
            }

            // Register the options for this authentication scheme
            _services.Configure(_authenticationScheme, configureOptions);
            
            // Register HttpContextAccessor - required for domain resolution
            _services.AddHttpContextAccessor();
            
            // Register HttpClient - required for fetching OIDC configuration per domain
            _services.AddHttpClient();
            
            // Register the startup filter to resolve domain early in the request pipeline
            _services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IStartupFilter, Auth0CustomDomainStartupFilter>(
                    _ => new Auth0CustomDomainStartupFilter(_authenticationScheme)));
            
            // Register the post-configure options to set up custom ConfigurationManager
            _services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, Auth0CustomDomainsOpenIdConnectPostConfigureOptions>());
        }

        private void EnableWithAccessToken(Action<Auth0WebAppWithAccessTokenOptions> configureOptions)
        {
            _accessTokenConfigured = true;

            var auth0WithAccessTokensOptions = new Auth0WebAppWithAccessTokenOptions();

            configureOptions(auth0WithAccessTokensOptions);

            ValidateOptions(_options);

            // GetAccessTokenAsync (MRRT) resolves an IHttpClientFactory to exchange the refresh
            // token when no Backchannel is configured. Register it here so the factory is always
            // available.
            _services.AddHttpClient();

            // GetAccessTokenAsync encrypts the mfa_token into the MfaRequiredException blob on the
            // mfa_required path. That path is reachable whenever refresh tokens are in use, even
            // without WithAuthenticationApiClient(), so the protector must be registered here too —
            // otherwise the mfa_required response would surface as an opaque DI resolution failure
            // instead of the typed exception. TryAddSingleton keeps WithAuthenticationApiClient()'s
            // own registration idempotent. Depends only on IDataProtectionProvider, which ASP.NET
            // Core registers by default.
            _services.TryAddSingleton<IMfaTokenProtector>(sp =>
                new MfaTokenProtector(sp.GetRequiredService<IDataProtectionProvider>()));

            _services.Configure(_authenticationScheme, configureOptions);
            _services.AddOptions<OpenIdConnectOptions>(_authenticationScheme)
                .Configure(options =>
                {
                    options.ResponseType = OpenIdConnectResponseType.Code;

                    if (!string.IsNullOrEmpty(auth0WithAccessTokensOptions.Scope))
                    {
                        options.Scope.AddRange(auth0WithAccessTokensOptions.Scope.Split(" "));
                    }

                    if (auth0WithAccessTokensOptions.UseRefreshTokens)
                    {
                        options.Scope.AddSafe("offline_access");
                    }

                    options.Events.OnRedirectToIdentityProvider = Utils.ProxyEvent(CreateOnRedirectToIdentityProvider(_authenticationScheme), options.Events.OnRedirectToIdentityProvider);
                });
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(string authenticationScheme)
        {
            return (context) =>
            {
                var optionsWithAccessToken = context.HttpContext.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppWithAccessTokenOptions>>().Get(authenticationScheme);

                if (!string.IsNullOrWhiteSpace(optionsWithAccessToken.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", optionsWithAccessToken.Audience);
                }

                if (context.Properties.Items.ContainsKey(Auth0AuthenticationParameters.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", context.Properties.Items[Auth0AuthenticationParameters.Audience]);
                }

                return Task.CompletedTask;
            };
        }

        private static void ValidateOptions(Auth0WebAppOptions options)
        {
            // Under mTLS the certificate is the credential; WithMtls has already enforced exclusivity.
            if (options.UseMtls)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(options.ClientSecret) && options.ClientAssertionSecurityKey == null)
            {
                throw new InvalidOperationException("Both Client Secret and Client Assertion can not be null when requesting an access token, one or the other has to be set.");
            }

            if (!string.IsNullOrWhiteSpace(options.ClientSecret) && options.ClientAssertionSecurityKey != null)
            {
                throw new InvalidOperationException("Both Client Secret and Client Assertion can not be set at the same time when requesting an access token.");
            }
        }
    }
}
