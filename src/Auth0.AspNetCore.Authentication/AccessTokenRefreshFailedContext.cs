using Microsoft.AspNetCore.Http;
using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Provides the details of a failed access-token refresh to subscribers of
    /// <see cref="Auth0WebAppWithAccessTokenEvents.OnAccessTokenRefreshFailed"/>, so they can
    /// distinguish a terminal failure (such as an <c>invalid_grant</c> for a revoked or expired
    /// refresh token, which warrants a re-login) from a transient one (such as a timeout or a
    /// rate-limit, which may be retried).
    /// </summary>
    public class AccessTokenRefreshFailedContext
    {
        private AccessTokenRefreshFailedContext(HttpContext httpContext, string? audience, string? scope, int? statusCode, string? error, string? errorDescription, Exception? exception)
        {
            HttpContext = httpContext;
            Audience = audience;
            Scope = scope;
            StatusCode = statusCode;
            Error = error;
            ErrorDescription = errorDescription;
            Exception = exception;
        }

        /// <summary>
        /// Creates a context for a failure where the token endpoint returned a non-success
        /// HTTP response. <see cref="Exception"/> is left <c>null</c>.
        /// </summary>
        internal static AccessTokenRefreshFailedContext FromHttpRejection(HttpContext httpContext, string? audience, string? scope, int? statusCode, string? error, string? errorDescription) =>
            new AccessTokenRefreshFailedContext(httpContext, audience, scope, statusCode, error, errorDescription, exception: null);

        /// <summary>
        /// Creates a context for a failure where the refresh threw before producing an HTTP
        /// response (for example a transport failure, timeout, or misconfiguration).
        /// <see cref="StatusCode"/>, <see cref="Error"/>, and <see cref="ErrorDescription"/> are left <c>null</c>.
        /// </summary>
        internal static AccessTokenRefreshFailedContext FromException(HttpContext httpContext, string? audience, string? scope, Exception exception) =>
            new AccessTokenRefreshFailedContext(httpContext, audience, scope, statusCode: null, error: null, errorDescription: null, exception: exception);

        /// <summary>
        /// The current <see cref="HttpContext"/>, allowing you to sign the user out, challenge
        /// for re-login, or resolve services to react to the failure.
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// The audience the token was being requested for, when one was resolved.
        /// </summary>
        public string? Audience { get; }

        /// <summary>
        /// The scope the token was being requested for, when one was resolved.
        /// </summary>
        public string? Scope { get; }

        /// <summary>
        /// The HTTP status code returned by the token endpoint, when the failure was an HTTP
        /// rejection. <c>null</c> when the request never produced a response (for example a
        /// transport failure — see <see cref="Exception"/>).
        /// </summary>
        public int? StatusCode { get; }

        /// <summary>
        /// The <c>error</c> code from the token endpoint's error response (for example
        /// <c>invalid_grant</c>), when present.
        /// </summary>
        public string? Error { get; }

        /// <summary>
        /// The <c>error_description</c> from the token endpoint's error response, when present.
        /// </summary>
        public string? ErrorDescription { get; }

        /// <summary>
        /// The exception that caused the failure, when the refresh threw rather than returning
        /// an HTTP error (for example a transport failure, timeout, or misconfiguration).
        /// <c>null</c> when the failure was an HTTP rejection — see <see cref="StatusCode"/>,
        /// <see cref="Error"/>, and <see cref="ErrorDescription"/>.
        /// May contain transport/diagnostic detail; log server-side only, do not surface to end users.
        /// </summary>
        public Exception? Exception { get; }
    }
}
