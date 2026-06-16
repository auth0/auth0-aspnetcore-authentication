using System;
using System.Net;
using System.Runtime.Serialization;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using Auth0.AspNetCore.Authentication.Exceptions;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Thrown by <see cref="HttpContextExtensions.GetAccessTokenAsync"/> when a token exchange
    /// returns an <c>mfa_required</c> error. Carries the <see cref="MfaToken"/> needed to drive
    /// the MFA challenge/verify flow via <see cref="AuthenticationApi.IAuthenticationApiClient"/>.
    /// </summary>
    [Serializable]
    public class MfaRequiredException : ErrorApiException
    {
        /// <summary>
        /// Creates an <see cref="MfaRequiredException"/> carrying the encrypted <c>mfa_token</c> blob
        /// and the status code / error details from the failed exchange.
        /// </summary>
        public MfaRequiredException(string? mfaToken, HttpStatusCode statusCode, ApiError? apiError = null)
            : this(mfaToken, null, statusCode, apiError)
        {
        }

        /// <summary>
        /// Creates an <see cref="MfaRequiredException"/> carrying the encrypted <c>mfa_token</c> blob,
        /// the available <paramref name="mfaRequirements"/>, and the status code / error details.
        /// </summary>
        public MfaRequiredException(string? mfaToken, MfaRequirements? mfaRequirements, HttpStatusCode statusCode, ApiError? apiError = null)
            : base(statusCode, apiError)
        {
            MfaToken = mfaToken;
            MfaRequirements = mfaRequirements;
        }

        /// <summary>The encrypted, integrity-protected, self-expiring <c>mfa_token</c> blob. Opaque to the
        /// application: pass it back to <see cref="AuthenticationApi.IAuthenticationApiClient"/>
        /// methods, which decrypt it internally. Valid for 5 minutes.</summary>
        public string? MfaToken { get; }

        /// <summary>The MFA factors/challenge types Auth0 reported as available, when present.</summary>
        public MfaRequirements? MfaRequirements { get; }

        /// <inheritdoc />
        protected MfaRequiredException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
            MfaToken = serializationInfo.GetString(nameof(MfaToken));
        }

        /// <inheritdoc />
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // MfaRequirements is intentionally not serialized: the type is not [Serializable] and
            // the recoverable MFA flow runs within a single request.
            base.GetObjectData(info, context);
            info.AddValue(nameof(MfaToken), MfaToken);
        }
    }
}
