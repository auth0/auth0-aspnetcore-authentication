using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Mvc
{
    public class OpenIdConnectEventsFactory
    {
        public static OpenIdConnectEvents Create(Auth0Options auth0Options)
        {
            return new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = CreateOnRedirectToIdentityProvider(auth0Options),
                OnRedirectToIdentityProviderForSignOut = CreateOnRedirectToIdentityProviderForSignOut(auth0Options),
                OnTokenValidated = CreateOnTokenValidated(auth0Options),

                OnAccessDenied = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAccessDenied),
                OnAuthenticationFailed = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthenticationFailed),
                OnAuthorizationCodeReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthorizationCodeReceived),
                OnMessageReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnMessageReceived),
                OnRemoteFailure = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRemoteFailure),
                OnRemoteSignOut = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRemoteSignOut),
                OnSignedOutCallbackRedirect = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnSignedOutCallbackRedirect),
                OnTicketReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTicketReceived),
                OnTokenResponseReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTokenResponseReceived),
                OnUserInformationReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnUserInformationReceived),
            };
        }

        private static Func<T, Task> ProxyEvent<T>(Func<T, Task> original)
        {
            return (T context) =>
            {
                return original != null ? original(context) : Task.CompletedTask;
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
                try
                {
                    IdTokenValidator.Validate(auth0Options, context.SecurityToken, context.Properties.Items);
                }
                catch (IdTokenValidationException ex)
                {
                    context.Fail(ex.Message);
                }

                if (auth0Options.OpenIdConnectEvents != null && auth0Options.OpenIdConnectEvents.OnTokenValidated != null)
                {
                    return auth0Options.OpenIdConnectEvents.OnTokenValidated(context);
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

    }
}
