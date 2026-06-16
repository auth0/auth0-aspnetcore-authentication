using System;
using System.Net;
using System.Runtime.Serialization;
using Auth0.AspNetCore.Authentication.Exceptions;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Thrown when an encrypted <c>mfa_token</c> blob (see <see cref="MfaRequiredException.MfaToken"/>)
    /// has passed its 5-minute lifetime. The MFA flow must be restarted to obtain a fresh token.
    /// </summary>
    [Serializable]
    public class MfaTokenExpiredException : ErrorApiException
    {
        private static ApiError DefaultError => new ApiError
        {
            Error = "mfa_token_expired",
            Message = "The MFA token has expired. Restart the MFA flow to obtain a new one."
        };

        /// <summary>Creates an <see cref="MfaTokenExpiredException"/> with a default error payload.</summary>
        public MfaTokenExpiredException()
            : base(HttpStatusCode.Unauthorized, DefaultError)
        {
        }

        /// <inheritdoc />
        protected MfaTokenExpiredException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }
}
