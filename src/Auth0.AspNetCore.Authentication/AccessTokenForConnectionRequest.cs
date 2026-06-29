namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Describes a request for a federated connection (Token Vault) access token —
    /// a third-party API token (e.g. Google, GitHub) for the logged-in user.
    /// </summary>
    public class AccessTokenForConnectionRequest
    {
        /// <summary>
        /// The federated connection to retrieve an access token for (e.g. "google-oauth2").
        /// Required.
        /// </summary>
        public string Connection { get; set; } = null!;

        /// <summary>
        /// Optional login hint forwarded to the token endpoint to disambiguate which linked
        /// identity to use. This is the provider-side identity provider user ID (e.g. a Google
        /// user ID) — not the Auth0 user <c>sub</c> and not the user's email.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// When <c>true</c>, always exchanges the refresh token for a new connection token,
        /// ignoring any cached token. Defaults to <c>false</c>.
        /// </summary>
        public bool ForceRefresh { get; set; }
    }
}
