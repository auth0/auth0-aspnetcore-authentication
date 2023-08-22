﻿using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    internal class OpenIdConnectEventsFactory
    {
        internal static OpenIdConnectEvents Create(Auth0WebAppOptions auth0Options)
        {
            return new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRedirectToIdentityProvider, CreateOnRedirectToIdentityProvider(auth0Options)),
                OnRedirectToIdentityProviderForSignOut = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnRedirectToIdentityProviderForSignOut, CreateOnRedirectToIdentityProviderForSignOut(auth0Options)),
                OnTokenValidated = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnTokenValidated, CreateOnTokenValidated(auth0Options)),

                OnAccessDenied = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAccessDenied),
                OnAuthenticationFailed = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthenticationFailed),
                OnAuthorizationCodeReceived = ProxyEvent(auth0Options.OpenIdConnectEvents?.OnAuthorizationCodeReceived, CreateOnAuthorizationCodeReceived(auth0Options)),
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

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProvider(Auth0WebAppOptions auth0Options)
        {
            return (context) =>
            {
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

                return Task.CompletedTask;
            };
        }

        private static Func<RedirectContext, Task> CreateOnRedirectToIdentityProviderForSignOut(Auth0WebAppOptions auth0Options)
        {
            return (context) =>
            {
                var logoutUri = $"https://{auth0Options.Domain}/v2/logout?client_id={auth0Options.ClientId}";
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

        private static Func<TokenValidatedContext, Task> CreateOnTokenValidated(Auth0WebAppOptions auth0Options)
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

                return Task.CompletedTask;
            };
        }


        private static Func<AuthorizationCodeReceivedContext, Task> CreateOnAuthorizationCodeReceived(Auth0WebAppOptions auth0Options)
        {
            return (context) =>
            {
                if (auth0Options.ClientAssertionSecurityKey != null)
                {
                    context.TokenEndpointRequest?.SetParameter("client_assertion", new JwtTokenFactory(auth0Options.ClientAssertionSecurityKey, auth0Options.ClientAssertionSecurityKeyAlgorithm ?? SecurityAlgorithms.RsaSha256)
                       .GenerateToken(auth0Options.ClientId, $"https://{auth0Options.Domain}/", auth0Options.ClientId
                    ));

                    context.TokenEndpointRequest?.SetParameter("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                }

                return Task.CompletedTask;
            };
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
