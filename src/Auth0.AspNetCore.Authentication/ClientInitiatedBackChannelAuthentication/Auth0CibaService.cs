using System;
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

    public Auth0CibaService(
        IAuthenticationApiClient authenticationApiClient,
        IOptions<Auth0WebAppOptions> optionsAccessor,
        ILogger<Auth0CibaService> logger)
    {
        _authenticationApiClient = authenticationApiClient;
        _options = optionsAccessor.Value;
        _logger = logger;
    }

    public async Task<CibaInitiationDetails> InitiateAuthenticationAsync(CibaInitiationRequest request)
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

    public async Task<CibaCompletionDetails> PollForTokensAsync(CibaInitiationDetails initDetails)
    {
        var request = new ClientInitiatedBackchannelAuthorizationTokenRequest()
        {
            ClientId = _options.ClientId,
            ClientSecret = _options.ClientSecret,
            ClientAssertionSecurityKey = _options.ClientAssertionSecurityKey,
            ClientAssertionSecurityKeyAlgorithm = _options.ClientAssertionSecurityKeyAlgorithm,
            AuthRequestId = initDetails.AuthRequestId
        };

        while (true)
        {
            _logger.LogDebug($"Polling CIBA token endpoint for auth_req_id: {initDetails.AuthRequestId} ");
            try
            {
                var response = await _authenticationApiClient.GetTokenAsync(request);
               
                return new CibaCompletionDetails
                {
                    AccessToken = response.AccessToken,
                    IdToken = response.IdToken,
                    TokenType = response.TokenType,
                    Scope = response.Scope,
                    ExpiresIn = response.ExpiresIn,
                    RefreshToken = response.RefreshToken,
                    IsSuccessful = true,
                    IsAuthenticationPending = false,
                };
            }
            catch (ErrorApiException ex)
            {
                _logger.LogWarning(
                    ex,
                    $"CIBA polling error for auth_req_id: {initDetails.AuthRequestId}." +
                    $" Error: {ex.ApiError.Error}, Description: {ex.ApiError.Message}");

                if (ex.ApiError.Error.Contains("authorization_pending", StringComparison.OrdinalIgnoreCase))
                {
                    await Task.Delay(TimeSpan.FromSeconds(initDetails.Interval ?? 5));
                    continue;
                }

                return new CibaCompletionDetails
                {
                    IsAuthenticationPending = false,
                    Error = ex.ApiError.Error,
                    ErrorMessage = ex.ApiError.Message,
                    IsSuccessful = false
                };
            }
        }
    }
}