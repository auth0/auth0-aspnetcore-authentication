namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Describes a request for an access token, optionally targeting a specific
    /// audience and/or scope.
    /// </summary>
    public class AccessTokenRequest
    {
        /// <summary>
        /// The audience to request an access token for. When omitted, the audience
        /// configured via <see cref="Auth0WebAppWithAccessTokenOptions.Audience"/> is used.
        /// </summary>
        public string? Audience { get; set; }

        /// <summary>
        /// The scopes to request. Merged (order-preserving union) with the configured
        /// default scopes for the resolved audience.
        /// </summary>
        public string? Scope { get; set; }
    }
}
