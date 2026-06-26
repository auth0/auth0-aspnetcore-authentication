using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Thrown when a Custom Token Exchange  fails — either client-side validation of the
    /// request, or rejection by the Auth0 token endpoint. Carries the token-endpoint status code and
    /// error details when the failure came from the network; never carries token-bearing bytes.
    /// </summary>
    public class CustomTokenExchangeException : Exception
    {
        /// <summary>The HTTP status code returned by the token endpoint, when the failure was a rejection.</summary>
        public int? StatusCode { get; }

        /// <summary>The <c>error</c> code from the token endpoint's error body, when present.</summary>
        public string? Error { get; }

        /// <summary>The <c>error_description</c> from the token endpoint's error body, when present.</summary>
        public string? ErrorDescription { get; }

        /// <summary>Creates an exception for a client-side validation failure.</summary>
        public CustomTokenExchangeException(string message) : base(message)
        {
        }

        /// <summary>Creates an exception for a token-endpoint rejection.</summary>
        public CustomTokenExchangeException(int? statusCode, string? error, string? errorDescription)
            : base(BuildMessage(statusCode, error, errorDescription))
        {
            StatusCode = statusCode;
            Error = error;
            ErrorDescription = errorDescription;
        }

        private static string BuildMessage(int? statusCode, string? error, string? errorDescription)
        {
            var code = error ?? "token_exchange_failed";
            var description = errorDescription ?? "The custom token exchange was rejected by the token endpoint.";
            return statusCode.HasValue
                ? $"Custom token exchange failed ({statusCode}): {code} - {description}"
                : $"Custom token exchange failed: {code} - {description}";
        }
    }
}
