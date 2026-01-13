using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.PushedAuthorizationRequest;
using Auth0.AspNetCore.Authentication.CustomDomains;

namespace Auth0.AspNetCore.Authentication
{
    internal class OpenIdConnectEventsFactory
    {
        internal static OpenIdConnectEvents Create(Auth0WebAppOptions auth0Options, OpenIdConnectOptions oidcOptions, Auth0CustomDomainsOptions? customDomainsOptions = null)
        {
            return new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRedirectToIdentityProvider, CreateOnRedirectToIdentityProvider(auth0Options, oidcOptions, customDomainsOptions)),
                OnRedirectToIdentityProviderForSignOut = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRedirectToIdentityProviderForSignOut, CreateOnRedirectToIdentityProviderForSignOut(auth0Options, customDomainsOptions)),
                OnTokenValidated = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTokenValidated, CreateOnTokenValidated(auth0Options, customDomainsOptions)),

                OnAccessDenied = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAccessDenied),
                OnAuthenticationFailed = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthenticationFailed),
                OnAuthorizationCodeReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthorizationCodeReceived, CreateOnAuthorizationCodeReceived(auth0Options, customDomainsOptions)),
                OnMessageReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnMessageReceived),
                OnRemoteFailure = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRemoteFailure),
                OnRemoteSignOut = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRemoteSignOut),
                OnSignedOutCallbackRedirect = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnSignedOutCallbackRedirect),
                OnTicketReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTicketReceived),
                OnTokenResponseReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTokenResponseReceived),
                OnUserInformationReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnUserInformationReceived),
            };
        }

        private static Func<T, Task> ProxyEvent<T>(Func<T, Task>? originalHandler, Func<T, Task>? newHandler = null)
        {
            return async (context) =>
            {
                if (newHandler != null)
                {
                    await newHandler(context);
                }

                if (originalHandler != null)
                {
                    await originalHandler(context);
                }
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(Auth0WebAppOptions auth0Options, OpenIdConnectOptions oidcOptions, Auth0CustomDomainsOptions? customDomainsOptions)
        {
            return async (context) =>
            {
                // Store the resolved domain in the authentication state (Properties.Items) so it can be validated
                // when the token returns. The StartupFilter already resolved it and cached it in HttpContext.Items.
                if (customDomainsOptions is { IsMultipleCustomDomainsEnabled: true })
                {
                    var resolvedDomain = context.HttpContext.GetResolvedDomain();
                    if (!string.IsNullOrWhiteSpace(resolvedDomain))
                    {
                        // Adds to the encrypted state parameter that will be available even in callbacks
                        context.Properties.Items[Auth0Constants.ResolvedDomainKey] = resolvedDomain;
                    }
                }

                // Set auth0Client querystring parameter for /authorize
                context.ProtocolMessage.SetParameter("auth0Client", Utils.CreateAgentString());

                foreach (var extraParam in GetAuthorizeParameters(auth0Options, context.Properties.Items))
                {
                    context.ProtocolMessage.SetParameter(extraParam.Key, extraParam.Value);
                }

                if (!string.IsNullOrWhiteSpace(auth0Options.Organization) && !context.Properties.Items.ContainsKey(Auth0AuthenticationParameters.Organization))
                {
                    context.Properties.Items[Auth0AuthenticationParameters.Organization] = auth0Options.Organization;
                }

                if (auth0Options.UsePushedAuthorization)
                {
                    await PushedAuthorizationRequestHandler.HandleAsync(context, oidcOptions);
                }
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProviderForSignOut(Auth0WebAppOptions auth0Options, Auth0CustomDomainsOptions? customDomainsOptions)
        {
            return (context) =>
            {
                // Prefer issuer from the authenticated principal
                var issuer = context.HttpContext.User?.FindFirst("iss")?.Value;
                
                // Fall back to the domain resolved by StartupFilter (cached in HttpContext.Items)
                if (string.IsNullOrWhiteSpace(issuer))
                {
                    issuer = context.HttpContext.GetResolvedDomain();
                }

                var authority = ToAuthority(issuer ?? $"https://{auth0Options.Domain}");
                var logoutUri = $"{authority}/v2/logout?client_id={auth0Options.ClientId}";

                var postLogoutUri = context.Properties.RedirectUri;
                var parameters = GetExtraParameters(context.Properties.Items);

                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    if (postLogoutUri.StartsWith("/"))
                    {
                        // transform to absolute
                        var request = context.Request;
                        postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                    }

                    logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                }

                foreach (var (key, value) in parameters)
                {
                    if (!string.IsNullOrEmpty(value))
                    {
                        logoutUri += $"&{key}={Uri.EscapeDataString(value)}";
                    }
                    else
                    {
                        logoutUri += $"&{key}";
                    }
                }

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            };
        }

        private static Func<TokenValidatedContext, Task> CreateOnTokenValidated(Auth0WebAppOptions auth0Options, Auth0CustomDomainsOptions? customDomainsOptions)
        {
            return (context) =>
            {
                try
                {
                    IdTokenValidator.Validate(auth0Options, context.SecurityToken, context.Properties?.Items);
                }
                catch (IdTokenValidationException ex)
                {
                    context.Fail(ex.Message);
                }

                // When the issuer is resolved per request, validate it against the issuer stored in the protected state.
                // This is important because we would have skipped issuer validation in the case of Multiple Custom Domains.
                if (customDomainsOptions is { IsMultipleCustomDomainsEnabled: true } && context.Properties?.Items != null &&
                    context.Properties.Items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var expectedIssuer) &&
                    !string.IsNullOrWhiteSpace(expectedIssuer))
                {
                    var tokenIssuer = context.SecurityToken.Issuer;
                    var expectedAuthority = ToAuthority(expectedIssuer);

                    var ok = tokenIssuer.Equals(expectedAuthority, StringComparison.OrdinalIgnoreCase) ||
                             tokenIssuer.Equals(expectedAuthority + "/", StringComparison.OrdinalIgnoreCase);

                    if (!ok)
                    {
                        context.Fail($"Token issuer '{tokenIssuer}' does not match expected issuer '{expectedAuthority}'.");
                    }
                }

                return Task.CompletedTask;
            };
        }


        private static Func<AuthorizationCodeReceivedContext, Task> CreateOnAuthorizationCodeReceived(Auth0WebAppOptions auth0Options, Auth0CustomDomainsOptions? customDomainsOptions)
        {
            return async (context) =>
            {
                if (auth0Options.ClientAssertionSecurityKey != null)
                {
                    var issuer = context.Properties?.Items != null && context.Properties.Items.TryGetValue(Auth0Constants.ResolvedDomainKey, out var storedIssuer)
                        ? storedIssuer
                        : null;
                    
                    if (string.IsNullOrWhiteSpace(issuer))
                    {
                        var resolvedDomain = context.HttpContext.GetResolvedDomain();
                        if (string.IsNullOrWhiteSpace(resolvedDomain) && customDomainsOptions?.DomainResolver != null)
                        {
                            resolvedDomain = await customDomainsOptions.DomainResolver(context.HttpContext).ConfigureAwait(false);
                        }
                        resolvedDomain ??= auth0Options.Domain;
                        issuer = $"https://{resolvedDomain}/";
                    }

                    var audience = ToAuthority(issuer) + "/";
                    context.TokenEndpointRequest?.SetParameter("client_assertion", new JwtTokenFactory(auth0Options.ClientAssertionSecurityKey, auth0Options.ClientAssertionSecurityKeyAlgorithm ?? SecurityAlgorithms.RsaSha256)
                       .GenerateToken(auth0Options.ClientId, audience, auth0Options.ClientId
                    ));

                    context.TokenEndpointRequest?.SetParameter("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                }
            };
        }

        private static string ToAuthority(string issuerOrAuthority)
        {
            var normalized = issuerOrAuthority.Trim().TrimEnd('/');

            if (normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return normalized;
            }

            return $"https://{normalized}";
        }

        private static IDictionary<string, string?> GetAuthorizeParameters(Auth0WebAppOptions auth0Options, IDictionary<string, string?> authSessionItems)
        {
            var parameters = new Dictionary<string, string?>();

            if (!string.IsNullOrEmpty(auth0Options.Organization))
            {
                parameters["organization"] = auth0Options.Organization;
            }

            // Extra Parameters
            if (auth0Options.LoginParameters != null)
            {
                foreach (var (key, value) in auth0Options.LoginParameters)
                {
                    parameters[key] = value;
                }
            }

            // Any Auth0 specific parameter
            foreach (var item in GetExtraParameters(authSessionItems))
            {
                var value = item.Value;
                if (item.Key == "scope")
                {
                    // Openid is a required scope, meaning that when omitted we need to ensure it gets added.
                    if (value == null)
                    {
                        value = "openid";
                    }
                    else if (!value.Contains("openid", StringComparison.CurrentCultureIgnoreCase))
                    {
                        value += " openid";
                    }
                }

                parameters[item.Key] = value;
            }

            return parameters;
        }

        private static IDictionary<string, string?> GetExtraParameters(IDictionary<string, string?> authSessionItems)
        {
            var parameters = new Dictionary<string, string?>();

            foreach (var (key, value) in authSessionItems.Where(item => item.Key.StartsWith($"{Auth0AuthenticationParameters.Prefix}:")))
            {
                parameters[key.Replace($"{Auth0AuthenticationParameters.Prefix}:", "")] = value;
            }

            return parameters;
        }

    }
}
