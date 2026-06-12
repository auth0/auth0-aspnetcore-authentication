namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// The outcome of a refresh-token exchange: either a successful <see cref="Response"/>
    /// or, on an HTTP rejection, the status code and parsed error details from the body.
    /// </summary>
    internal class TokenRefreshResult
    {
        /// <summary>The successful token response, or <c>null</c> when the exchange failed.</summary>
        public AccessTokenResponse? Response { get; set; }

        /// <summary>The HTTP status code returned by the token endpoint when the exchange failed.</summary>
        public int? StatusCode { get; set; }

        /// <summary>The <c>error</c> code from the token endpoint's error body, when present.</summary>
        public string? Error { get; set; }

        /// <summary>The <c>error_description</c> from the token endpoint's error body, when present.</summary>
        public string? ErrorDescription { get; set; }

        public bool IsSuccess => Response != null;

        public static TokenRefreshResult Success(AccessTokenResponse response) => new TokenRefreshResult { Response = response };
    }
}
