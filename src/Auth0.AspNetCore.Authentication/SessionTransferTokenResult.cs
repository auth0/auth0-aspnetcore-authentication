namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// The result of a Session Transfer Token exchange. The STT is opaque, single-use, and
    /// short-lived (~60s) — never persist it. It is meant to be placed on a redirect to the target
    /// app immediately (see <c>HttpContext.BuildSessionTransferRedirect</c>).
    /// </summary>
    /// <remarks>
    /// There is deliberately no <c>Act</c> claim here: <c>act</c> appears only on the target's session
    /// after the STT is redeemed at <c>/authorize</c>, not on the initiator's exchange response.
    /// </remarks>
    public class SessionTransferTokenResult
    {
        /// <summary>The opaque, single-use session transfer token. Never persist it.</summary>
        public string SessionTransferToken { get; set; } = null!;

        /// <summary>
        /// The <c>issued_token_type</c>; for an STT this is
        /// <see cref="Auth0Constants.SessionTransferTokenType"/>. Branch on this, not on
        /// <see cref="TokenType"/>.
        /// </summary>
        public string IssuedTokenType { get; set; } = null!;

        /// <summary>The token lifetime in seconds (typically ~60).</summary>
        public int ExpiresIn { get; set; }

        /// <summary>The <c>token_type</c>; informational only (typically <c>N_A</c>). Never branch on it.</summary>
        public string? TokenType { get; set; }

        /// <summary>The granted scopes, when returned.</summary>
        public string? Scope { get; set; }
    }
}
