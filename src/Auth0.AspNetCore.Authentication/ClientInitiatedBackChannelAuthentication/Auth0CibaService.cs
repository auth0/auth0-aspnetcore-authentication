using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models.Ciba;
using Auth0.Core.Exceptions;

namespace Auth0.AspNetCore.Authentication.ClientInitiatedBackChannelAuthentication;

internal class Auth0CibaService : IAuth0CibaService
{
    private readonly IAuthenticationApiClient _authenticationApiClient;
    private readonly Auth0WebAppOptions _options;
    private readonly ILogger<Auth0CibaService> _logger;

    /// <summary>
    /// Initiates an instance of Auth0CibaService which can be used to execute the CIBA workflow.
    /// </summary>
    /// <param name="authenticationApiClient">Instance of <see cref="Auth0.AuthenticationApi.IAuthenticationApiClient"/> </param>
    /// <param name="optionsAccessor"><see cref="Auth0WebAppOptions"/></param>
    /// <param name="logger"></param>
    public Auth0CibaService(
        IAuthenticationApiClient authenticationApiClient,
        IOptions<Auth0WebAppOptions> optionsAccessor,
        ILogger<Auth0CibaService> logger)
    {
        _authenticationApiClient = authenticationApiClient;
        _options = optionsAccessor.Value;
        _logger = logger;
    }

    /// <inheritdoc cref="Auth0.AspNetCore.Authentication.ClientInitiatedBackChannelAuthentication.IAuth0CibaService.InitiateAuthenticationAsync"/>
    public async Task<CibaInitiationDetails> InitiateAuthenticationAsync(
        CibaInitiationRequest request)
    {
        try
        {
            var cibaRequest = new ClientInitiatedBackchannelAuthorizationRequest
            {
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                ClientAssertionSecurityKey = _options.ClientAssertionSecurityKey,
                ClientAssertionSecurityKeyAlgorithm = _options.ClientAssertionSecurityKeyAlgorithm,
                Audience = request.Audience,
                LoginHint = request.LoginHint,
                Scope = request.Scope,
                RequestExpiry = request.RequestExpiry,
                AdditionalProperties = request.AdditionalProperties,
                BindingMessage = request.BindingMessage,
            };

            _logger.LogInformation("Initiating CIBA request!");
            var response = await _authenticationApiClient.ClientInitiatedBackchannelAuthorization(cibaRequest);

            return new CibaInitiationDetails()
            {
                AuthRequestId = response.AuthRequestId,
                ExpiresIn = response.ExpiresIn,
                Interval = response.Interval,
                IsSuccessful = true,
                ErrorMessage = null
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error initiating CIBA request");
            throw;
        }
    }

    /// <inheritdoc cref="Auth0.AspNetCore.Authentication.ClientInitiatedBackChannelAuthentication.IAuth0CibaService.PollForTokensAsync"/>
    public async Task<CibaCompletionDetails> PollForTokensAsync(
        CibaInitiationDetails initDetails, CancellationToken cancellationToken)
    {
        var request = new ClientInitiatedBackchannelAuthorizationTokenRequest()
        {
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            ClientAssertionSecurityKey = _options.ClientAssertionSecurityKey,
            ClientAssertionSecurityKeyAlgorithm = _options.ClientAssertionSecurityKeyAlgorithm,
            AuthRequestId = initDetails.AuthRequestId
        };

        var completionDetails = new CibaCompletionDetails()
        {
            IsSuccessful = false,
            IsAuthenticationPending = true
        };
        
        while (completionDetails is { IsAuthenticationPending: true, IsSuccessful: false })
        {
            _logger.LogDebug($"Polling CIBA token endpoint for auth_req_id: {initDetails.AuthRequestId} ");
            try
            {
                var response = await _authenticationApiClient.GetTokenAsync(request, cancellationToken);

                completionDetails.AccessToken = response.AccessToken;
                completionDetails.IdToken = response.IdToken;
                completionDetails.TokenType = response.TokenType;
                completionDetails.Scope = response.Scope;
                completionDetails.ExpiresIn = response.ExpiresIn;
                completionDetails.RefreshToken = response.RefreshToken;
                completionDetails.IsSuccessful = true;
                completionDetails.IsAuthenticationPending = false;
            }
            catch (ErrorApiException ex)
            {
                _logger.LogWarning(
                    ex,
                    $"CIBA polling error for auth_req_id: {initDetails.AuthRequestId}." +
                    $" Error: {ex.ApiError.Error}, Description: {ex.ApiError.Message}");

                if (ex.ApiError.Error.Contains("authorization_pending", StringComparison.OrdinalIgnoreCase))
                {
                    await Task.Delay(TimeSpan.FromSeconds(initDetails.Interval));
                    continue;
                }

                completionDetails.IsAuthenticationPending = false;
                completionDetails.Error = ex.ApiError.Error;
                completionDetails.ErrorMessage = ex.ApiError.Message;
                completionDetails.IsSuccessful = false;
            }
        }
        return completionDetails;
    }
}