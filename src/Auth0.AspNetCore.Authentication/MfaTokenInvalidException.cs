using System;
using System.Net;
using System.Runtime.Serialization;
using Auth0.AspNetCore.Authentication.Exceptions;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Thrown when an <c>mfa_token</c> value cannot be decrypted as a blob produced by this SDK —
    /// it was tampered with, malformed, or protected with a different key. The MFA flow must be
    /// restarted.
    /// </summary>
    [Serializable]
    public class MfaTokenInvalidException : ErrorApiException
    {
        private static ApiError DefaultError => new ApiError
        {
            Error = "mfa_token_invalid",
            Message = "The MFA token is invalid or could not be decrypted."
        };

        /// <summary>Creates an <see cref="MfaTokenInvalidException"/> with a default error payload.</summary>
        public MfaTokenInvalidException()
            : base(HttpStatusCode.Unauthorized, DefaultError)
        {
        }

        /// <inheritdoc />
        protected MfaTokenInvalidException(SerializationInfo serializationInfo, StreamingContext streamingContext)
            : base(serializationInfo, streamingContext)
        {
        }
    }
}
