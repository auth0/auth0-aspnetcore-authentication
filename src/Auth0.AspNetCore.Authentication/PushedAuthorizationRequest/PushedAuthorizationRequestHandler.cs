using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.Exceptions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.PushedAuthorizationRequest;

/// <summary>
/// Handler used to support Pushed Authorization Request with Microsoft's Open Id Connect package.
///
/// This is needed because there is no built-in support for PAR in ASP.NET Core.
/// Once https://github.com/dotnet/aspnetcore/issues/51686 is implemented, we should be able to replace our
/// internal implementation and rely on the official implementation.
/// </summary>
internal static class PushedAuthorizationRequestHandler
{
    public static async Task HandleAsync(RedirectContext context, OpenIdConnectOptions oidcOptions)
    {
        // Read the PAR Endpoint from the OIDC configuration.
        var oidcConfiguration =
            await oidcOptions.ConfigurationManager?.GetConfigurationAsync(default)!;

        // Trying to get the PAR endpoint from the property first, fallback to AdditionalData for older configs.
        string? parEndpoint = null;
        if (oidcConfiguration != null)
        {
            parEndpoint = oidcConfiguration?.PushedAuthorizationRequestEndpoint;
            if (string.IsNullOrEmpty(parEndpoint))
            {
                object? rawParEndpoint = string.Empty;
                oidcConfiguration.AdditionalData?.TryGetValue("pushed_authorization_request_endpoint", out rawParEndpoint);
                parEndpoint = rawParEndpoint as string;
            }
        }

        // If PAR was enabled in the options, but no `pushed_authorization_request_endpoint` value is found
        // in the OIDC configuration, we will throw an error.
        if (string.IsNullOrEmpty(parEndpoint))
        {
            throw new InvalidOperationException(
                "Trying to use pushed authorization, but no value for 'pushed_authorization_request_endpoint' was found in the open id configuration.");
        }
        
        var message = context.ProtocolMessage;
        var properties = context.Properties;
        var clientId = message.ClientId;
        
        // As the client_secret isn't send through the front-channel,
        // we need to ensure it is added when sending the request through the back-channel.
        message.SetParameter("client_secret", oidcOptions.ClientSecret);

        SetStateParameter(message, properties, oidcOptions);

        var parResponse = await PostAuthorizationParameters(message, parEndpoint, oidcOptions.Backchannel);
        
        SetAuthorizeParameters(message, clientId, parResponse);
        
        // Mark the request as handled to avoid it attaches state to the request to /authorize.
        context.HandleResponse();

        RedirectToAuthorizeEndpoint(context, context.ProtocolMessage);
    }

    /// <summary>
    /// Sets the State property on the provided <see cref="OpenIdConnectMessage"/> to a protected value of the <see cref="AuthenticationProperties"/>.
    /// </summary>
    /// <param name="message">The <see cref="OpenIdConnectMessage"/> for the current request.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/> for the current request.</param>
    /// <param name="options">The globally configured <see cref="OpenIdConnectOptions"/>.</param>
    /// <returns></returns>
    private static void SetStateParameter(OpenIdConnectMessage message,
        AuthenticationProperties properties, OpenIdConnectOptions options)
    {
        // When redeeming a 'code' for an AccessToken, this value is needed
        properties.Items.Add(OpenIdConnectDefaults.RedirectUriForCodePropertiesKey, message.RedirectUri);

        message.State = options.StateDataFormat.Protect(properties);
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="message">The <see cref="OpenIdConnectMessage"/> for the current request.</param>
    /// <param name="parEndpoint">The PAR endpoint used to post the authorization parameters.</param>
    /// <param name="httpClient">The <see cref="HttpClient"/> configured to use for the PAR request.</param>
    /// <returns>An instance of <see cref="ParResponse"/>, containing the response details of the PAR request.</returns>
    /// <exception cref="ErrorApiException"></exception>
    private static async Task<PushedAuthorizationRequestResponse> PostAuthorizationParameters(OpenIdConnectMessage message, string parEndpoint,
        HttpClient httpClient)
    {
        var requestBody = new FormUrlEncodedContent(message.Parameters);

        var response = await httpClient.PostAsync(parEndpoint, requestBody);

        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorApiException.CreateAsync(response).ConfigureAwait(false);
        }

        return (await response.Content.ReadFromJsonAsync<PushedAuthorizationRequestResponse>()) ?? new PushedAuthorizationRequestResponse();
    }

    /// <summary>
    /// Clears the parameters for the current <see cref="OpenIdConnectMessage"/>, and sets the PAR values (clientId and RequestUri)
    /// </summary>
    /// <param name="message">The <see cref="OpenIdConnectMessage"/> for the current request.</param>
    /// <param name="clientId">The currently configured client id used for the application.</param>
    /// <param name="parResponse"></param>
    private static void SetAuthorizeParameters(OpenIdConnectMessage message, string clientId, PushedAuthorizationRequestResponse parResponse)
    {
        // Remove all the parameters from the protocol message, and replace with what we got from the PAR response
        message.Parameters.Clear();
        // Then, set client id and request uri as parameters
        message.ClientId = clientId;
        message.RequestUri = parResponse.RequestUri;
    }

    /// <summary>
    /// Redirect to the authorize endpoint after successfully posting the parameters to the PAR endpoint.
    /// </summary>
    /// <param name="context">The original <see cref="RedirectContext"/> from the OpenId Connect handler.</param>
    /// <param name="message">The <see cref="OpenIdConnectMessage"/> for the current request.</param>
    private static void RedirectToAuthorizeEndpoint(RedirectContext context, OpenIdConnectMessage message)
    {
        var redirectUri = message.CreateAuthenticationRequestUrl();

        context.Response.Redirect(redirectUri);
    }

  
}