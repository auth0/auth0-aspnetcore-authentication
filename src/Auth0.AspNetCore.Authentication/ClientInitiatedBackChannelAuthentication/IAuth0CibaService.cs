using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Auth0.AuthenticationApi.Models.Ciba;

namespace Auth0.AspNetCore.Authentication.ClientInitiatedBackChannelAuthentication;

public class CibaInitiationDetails : ClientInitiatedBackchannelAuthorizationResponse
{
    /// <summary>
    /// Indicates whether the polling was successful.
    /// </summary>
    public bool IsSuccessful { get; init; } = true;
    
    /// <summary>
    /// Indicates any errors that occurred during the initiation of the CIBA request.
    /// </summary>
    public string? ErrorMessage { get; init; }
}

public class CibaInitiationRequest
{
    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.ClientInitiatedBackchannelAuthorizationRequest.BindingMessage"/>
    public string? BindingMessage { get; set; }

    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.LoginHint"/>
    public LoginHint? LoginHint { get; set; }

    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.ClientInitiatedBackchannelAuthorizationRequest.Scope"/>
    public string? Scope { get; set; }

    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.ClientInitiatedBackchannelAuthorizationRequest.Audience"/>
    public string? Audience { get; set; }

    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.ClientInitiatedBackchannelAuthorizationRequest.RequestExpiry"/>
    public int? RequestExpiry { get; set; }

    /// <inheritdoc cref="Auth0.AuthenticationApi.Models.Ciba.ClientInitiatedBackchannelAuthorizationRequest.AdditionalProperties"/>
    public IDictionary<string, string> AdditionalProperties { get; set; } = new Dictionary<string, string>();
}

public class CibaCompletionDetails : ClientInitiatedBackchannelAuthorizationTokenResponse
{
    /// <summary>
    /// Signifies if the authentication is pending.
    /// </summary>
    public bool IsAuthenticationPending { get; set; } = true;

    /// <summary>
    /// Signifies if the authentication is successful.
    /// </summary>
    public bool IsSuccessful { get; set; } = false;

    /// <summary>
    /// The error received in case of expiry or consent rejection
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// The error message received in case of expiry or consent rejection
    /// </summary>
    public string? ErrorMessage { get; set; }
}

public interface IAuth0CibaService
{
    /// <summary>
    /// Initiates a Client-Initiated Backchannel Authentication (CIBA) flow.
    /// </summary>
    /// <param name="request">Contains the information required for initiating the CIBA request.</param>
    Task<CibaInitiationDetails> InitiateAuthenticationAsync(CibaInitiationRequest request);

    /// <summary>
    /// Polls the token endpoint to check the status of a CIBA request and retrieve tokens upon completion.
    /// </summary>
    /// <param name="cibaInitiationDetails">The information required to poll for the CIBA status.</param>
    /// <param name="cancellationToken"><see cref="CancellationToken"/></param>
    /// <returns>Details about the CIBA completion status or the retrieved tokens.</returns>
    Task<CibaCompletionDetails> PollForTokensAsync(CibaInitiationDetails cibaInitiationDetails, CancellationToken cancellationToken = default);
}