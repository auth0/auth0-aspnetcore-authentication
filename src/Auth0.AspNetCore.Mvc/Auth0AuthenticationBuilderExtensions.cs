using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    public static class Auth0AuthenticationBuilderExtensions
    {
        /// <summary>
        /// Add Auth0 configuration using Open ID Connect
        /// </summary>
        /// <param name="builder">The original <see cref="AuthenticationBuilder"/> instance</param>
        /// <param name="configureOptions">A delegate used to configure the <see cref="Auth0Options"/></param>
        /// <returns>The <see cref="AuthenticationBuilder"/ instance that has been configured.</returns>
        public static AuthenticationBuilder AddAuth0Mvc(this AuthenticationBuilder builder, Action<Auth0Options> configureOptions)
        {
            var auth0Options = new Auth0Options();

            configureOptions(auth0Options);
            ValidateOptions(auth0Options);

            builder.AddCookie();
            builder.AddOpenIdConnect(Constants.AuthenticationScheme, options => ConfigureOpenIdConnect(options, auth0Options));

            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, Auth0OpenIdConnectPostConfigureOptions>());

            return builder;
        }

        /// <summary>
        /// Configure Open ID Connect based on the provided <see cref="Auth0Options"/>.
        /// </summary>
        /// <param name="oidcOptions">A reference to the <see cref="OpenIdConnectOptions"/> that needs to be configured./param>
        /// <param name="auth0Options">The provided <see cref="Auth0Options"/>.</param>
        private static void ConfigureOpenIdConnect(OpenIdConnectOptions oidcOptions, Auth0Options auth0Options)
        {
            oidcOptions.Authority = $"https://{auth0Options.Domain}";
            oidcOptions.ClientId = auth0Options.ClientId;
            oidcOptions.ClientSecret = auth0Options.ClientSecret;
            oidcOptions.Scope.Clear();
            oidcOptions.Scope.AddRange(auth0Options.Scope.Split(" "));
            oidcOptions.CallbackPath = new PathString(auth0Options.CallbackPath ?? Constants.DefaultCallbackPath);
            oidcOptions.SaveTokens = true;
            oidcOptions.ResponseType = auth0Options.ResponseType ?? oidcOptions.ResponseType;
            oidcOptions.Backchannel = auth0Options.Backchannel;

            oidcOptions.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                ValidIssuer = $"https://{auth0Options.Domain}/",
                ValidateAudience = true,
                ValidAudience = auth0Options.ClientId
            };

            oidcOptions.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = CreateOnRedirectToIdentityProvider(auth0Options),
                OnRedirectToIdentityProviderForSignOut = CreateOnRedirectToIdentityProviderForSignOut(auth0Options),
                OnTokenValidated = CreateOnTokenValidated(auth0Options),
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(Auth0Options auth0Options)
        {
            return (context) =>
            {
                // Set auth0Client querystring parameter for /authorize
                context.ProtocolMessage.SetParameter("auth0Client", Utils.CreateAgentString());

                if (!string.IsNullOrWhiteSpace(auth0Options.Audience))
                {
                    context.ProtocolMessage.SetParameter("audience", auth0Options.Audience);
                }

                foreach (var extraParam in GetAuthorizeParameters(auth0Options, context.Properties.Items))
                {
                    context.ProtocolMessage.SetParameter(extraParam.Key, extraParam.Value);
                }

                if (!string.IsNullOrWhiteSpace(auth0Options.Organization) && !context.Properties.Items.ContainsKey(Auth0AuthenticationParmeters.Organization))
                {
                    context.Properties.Items[Auth0AuthenticationParmeters.Organization] = auth0Options.Organization;
                }

                return Task.CompletedTask;
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProviderForSignOut(Auth0Options auth0Options)
        {
            return (context) =>
            {
                var logoutUri = $"https://{auth0Options.Domain}/v2/logout?client_id={auth0Options.ClientId}";
                var postLogoutUri = context.Properties.RedirectUri;

                if (!string.IsNullOrEmpty(postLogoutUri))
                {
                    if (postLogoutUri.StartsWith("/"))
                    {
                        // transform to absolute
                        var request = context.Request;
                        postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                    }

                    logoutUri += $"&returnTo={ Uri.EscapeDataString(postLogoutUri)}";
                }

                context.Response.Redirect(logoutUri);
                context.HandleResponse();

                return Task.CompletedTask;
            };
        }

        private static Func<TokenValidatedContext, Task> CreateOnTokenValidated(Auth0Options auth0Options)
        {
            return (context) =>
            {
                var organization = context.Properties.Items.ContainsKey(Auth0AuthenticationParmeters.Organization) ? context.Properties.Items[Auth0AuthenticationParmeters.Organization] : null;

                if (!string.IsNullOrWhiteSpace(organization))
                {
                    var organizationClaimValue = context.SecurityToken.Claims.SingleOrDefault(claim => claim.Type == "org_id")?.Value;

                    if (string.IsNullOrWhiteSpace(organizationClaimValue))
                    {
                        context.Fail("Organization claim must be a string present in the ID token.");
                    }
                    else if (organizationClaimValue != organization)
                    {
                        context.Fail($"Organization claim mismatch in the ID token; expected \"{organization}\", found \"{organizationClaimValue}\".");
                    }
                }

                if (auth0Options.Events != null && auth0Options.Events.OnTokenValidated != null)
                {
                    return auth0Options.Events.OnTokenValidated(context);
                }

                return Task.CompletedTask;
            };
        }

        private static IDictionary<string, string> GetAuthorizeParameters(Auth0Options auth0Options, IDictionary<string, string> authSessionItems)
        {
            var parameters = new Dictionary<string, string>();

            if (!string.IsNullOrEmpty(auth0Options.Organization))
            {
                parameters["organization"] = auth0Options.Organization;
            }

            // Extra Parameters
            if (auth0Options.ExtraParameters != null)
            {
                foreach (var extraParam in auth0Options.ExtraParameters)
                {
                    parameters[extraParam.Key] = extraParam.Value;
                }
            }

            // Any Auth0 specific parameter
            foreach (var item in authSessionItems.Where(item => item.Key.StartsWith($"{Auth0AuthenticationParmeters.Prefix}:")))
            {
                parameters[item.Key.Replace($"{Auth0AuthenticationParmeters.Prefix}:", "")] = item.Value;
            }

            return parameters;
        }

        private static void ValidateOptions(Auth0Options auth0Options)
        {
            var codeResponseTypes = new[] {
                OpenIdConnectResponseType.Code,
                OpenIdConnectResponseType.CodeIdToken
            };

            if (codeResponseTypes.Contains(auth0Options.ResponseType) && string.IsNullOrWhiteSpace(auth0Options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(auth0Options.ClientSecret), "Client Secret can not be null when using `code` or `code id_token` as the response_type.");
            }

            if (!string.IsNullOrWhiteSpace(auth0Options.Audience) && !codeResponseTypes.Contains(auth0Options.ResponseType))
            {
                throw new InvalidOperationException("Using Audience is only supported when using `code` or `code id_token` as the response_type.");
            }
        }
    }
}
