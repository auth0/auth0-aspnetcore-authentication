using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using Auth0.AspNetCore.Authentication.Exceptions;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.AuthenticationApi;

/// <inheritdoc cref="IAuthenticationApiClient"/>
/// <remarks>
/// Implemented over System.Text.Json with no dependency on the <c>Auth0.AuthenticationApi</c>
/// package (which is Newtonsoft-based). When that package is later integrated, the body of this
/// class becomes a mapping adapter onto it; the public contract (interface + Models) stays the
/// same, so consumers are unaffected.
/// </remarks>
public class AuthenticationApiClient : IAuthenticationApiClient
{
    private const string MfaOtpGrantType = "http://auth0.com/oauth/grant-type/mfa-otp";
    private const string MfaOobGrantType = "http://auth0.com/oauth/grant-type/mfa-oob";
    private const string MfaRecoveryCodeGrantType = "http://auth0.com/oauth/grant-type/mfa-recovery-code";

    private readonly HttpClient _httpClient;
    private readonly Auth0WebAppOptions _options;
    private readonly string _domain;
    private readonly bool _ownsHttpClient;
    private readonly IMfaTokenProtector _mfaTokenProtector;

    private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Creates a client targeting <paramref name="baseUri"/>, authenticating with <paramref name="options"/>'s client credentials.</summary>
    /// <param name="httpClient">The <see cref="HttpClient"/> to use for requests.</param>
    /// <param name="baseUri">The base URI for API requests.</param>
    /// <param name="options">The authentication options.</param>
    /// <param name="mfaTokenProtector">The protector for decrypting MFA token blobs.</param>
    /// <param name="ownsHttpClient">When <c>true</c> (the default), the supplied <see cref="HttpClient"/> is disposed when this client is disposed. Pass <c>false</c> when the <see cref="HttpClient"/> is owned by the caller (for example a shared backchannel client).</param>
    internal AuthenticationApiClient(HttpClient httpClient, Uri baseUri, Auth0WebAppOptions options, IMfaTokenProtector mfaTokenProtector, bool ownsHttpClient = true)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        BaseUri = baseUri ?? throw new ArgumentNullException(nameof(baseUri));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _mfaTokenProtector = mfaTokenProtector ?? throw new ArgumentNullException(nameof(mfaTokenProtector));
        _domain = baseUri.Host;
        _ownsHttpClient = ownsHttpClient;
    }

    /// <inheritdoc />
    public Uri BaseUri { get; }

    /// <inheritdoc />
    public Task<MfaChallengeResponse> MfaChallengeAsync(MfaChallengeRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var mfaContext = _mfaTokenProtector.Unprotect(request.MfaToken);

        var body = new Dictionary<string, string>
        {
            { "mfa_token", mfaContext.MfaToken },
            { "client_id", _options.ClientId }
        };
        if (!string.IsNullOrWhiteSpace(request.ChallengeType)) body.Add("challenge_type", request.ChallengeType!);
        if (!string.IsNullOrWhiteSpace(request.AuthenticatorId)) body.Add("authenticator_id", request.AuthenticatorId!);
        ApplyClientAuthentication(body);

        return PostFormAsync<MfaChallengeResponse>("mfa/challenge", body, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaOtpTokenResponse> GetTokenAsync(MfaOtpTokenRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var mfaContext = _mfaTokenProtector.Unprotect(request.MfaToken);

        var body = new Dictionary<string, string>
        {
            { "grant_type", MfaOtpGrantType },
            { "client_id", _options.ClientId },
            { "mfa_token", mfaContext.MfaToken },
            { "otp", request.Otp }
        };
        AddBoundAudienceScope(body, mfaContext);
        ApplyClientAuthentication(body);

        return PostFormAsync<MfaOtpTokenResponse>("oauth/token", body, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaOobTokenResponse> GetTokenAsync(MfaOobTokenRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var mfaContext = _mfaTokenProtector.Unprotect(request.MfaToken);

        var body = new Dictionary<string, string>
        {
            { "grant_type", MfaOobGrantType },
            { "client_id", _options.ClientId },
            { "mfa_token", mfaContext.MfaToken },
            { "oob_code", request.OobCode }
        };
        if (!string.IsNullOrWhiteSpace(request.BindingCode)) body.Add("binding_code", request.BindingCode!);
        AddBoundAudienceScope(body, mfaContext);
        ApplyClientAuthentication(body);

        return PostFormAsync<MfaOobTokenResponse>("oauth/token", body, cancellationToken);
    }

    /// <inheritdoc />
    public Task<MfaRecoveryCodeResponse> GetTokenAsync(MfaRecoveryCodeRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var mfaContext = _mfaTokenProtector.Unprotect(request.MfaToken);

        var body = new Dictionary<string, string>
        {
            { "grant_type", MfaRecoveryCodeGrantType },
            { "client_id", _options.ClientId },
            { "mfa_token", mfaContext.MfaToken },
            { "recovery_code", request.RecoveryCode }
        };
        AddBoundAudienceScope(body, mfaContext);
        ApplyClientAuthentication(body);

        return PostFormAsync<MfaRecoveryCodeResponse>("oauth/token", body, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<AssociateMfaAuthenticatorResponse> AssociateMfaAuthenticatorAsync(AssociateMfaAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        var bearer = ResolveAssociateToken(request.Token);

        using var message = new HttpRequestMessage(HttpMethod.Post, BuildUri("mfa/associate"))
        {
            Content = new StringContent(JsonSerializer.Serialize(request, SerializerOptions), Encoding.UTF8, "application/json")
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);

        return await SendAsync<AssociateMfaAuthenticatorResponse>(message, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IList<Authenticator>> ListMfaAuthenticatorsAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(accessToken)) throw new ArgumentNullException(nameof(accessToken));

        using var message = new HttpRequestMessage(HttpMethod.Get, BuildUri("mfa/authenticators"));
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        return await SendAsync<IList<Authenticator>>(message, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DeleteMfaAuthenticatorAsync(DeleteMfaAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));

        using var message = new HttpRequestMessage(HttpMethod.Delete, BuildUri($"mfa/authenticators/{Uri.EscapeDataString(request.AuthenticatorId)}"));
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", request.AccessToken);

        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    private async Task<T> PostFormAsync<T>(string path, Dictionary<string, string> body, CancellationToken cancellationToken)
    {
        var content = new FormUrlEncodedContent(body.Select(p => new KeyValuePair<string?, string?>(p.Key, p.Value)));
        using var message = new HttpRequestMessage(HttpMethod.Post, BuildUri(path)) { Content = content };
        return await SendAsync<T>(message, cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> SendAsync<T>(HttpRequestMessage message, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response).ConfigureAwait(false);

        var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        var result = await JsonSerializer.DeserializeAsync<T>(stream, SerializerOptions, cancellationToken).ConfigureAwait(false);
        return result!;
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw await ErrorApiException.CreateAsync(response).ConfigureAwait(false);
        }
    }

    private Uri BuildUri(string path) => new Uri($"https://{_domain}/{path}");

    // The grant calls replay the audience/scope bound into the blob so the new token targets the
    // same resource the original refresh did.
    private static void AddBoundAudienceScope(Dictionary<string, string> body, MfaTokenContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.Audience)) body["audience"] = context.Audience!;
        if (!string.IsNullOrWhiteSpace(context.Scope)) body["scope"] = context.Scope!;
    }

    // Token may be one of our encrypted mfa_token blobs OR a raw access token (enroll scope).
    // A blob we can decrypt yields the raw mfa_token; a value that isn't one of our blobs
    // (MfaTokenInvalidException) is an access token, used as-is. An expired blob is a genuine
    // error and is allowed to propagate.
    private string ResolveAssociateToken(string token)
    {
        try
        {
            return _mfaTokenProtector.Unprotect(token).MfaToken;
        }
        catch (MfaTokenInvalidException)
        {
            return token;
        }
    }

    private void ApplyClientAuthentication(Dictionary<string, string> body)
    {
        if (_options.ClientAssertionSecurityKey != null)
        {
            body.Add("client_assertion", new JwtTokenFactory(
                    _options.ClientAssertionSecurityKey,
                    _options.ClientAssertionSecurityKeyAlgorithm ?? SecurityAlgorithms.RsaSha256)
                .GenerateToken(_options.ClientId, $"https://{_domain}/", _options.ClientId));
            body.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        }
        else if (!string.IsNullOrEmpty(_options.ClientSecret))
        {
            body.Add("client_secret", _options.ClientSecret!);
        }
    }
}
