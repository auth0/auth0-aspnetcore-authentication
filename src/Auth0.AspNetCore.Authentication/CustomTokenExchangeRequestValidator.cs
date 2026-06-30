using System;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Validates a <see cref="CustomTokenExchangeRequest"/> client-side, before any network call.
    /// Throws <see cref="CustomTokenExchangeException"/> on the first violation.
    /// </summary>
    internal static class CustomTokenExchangeRequestValidator
    {
        public static void Validate(CustomTokenExchangeRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.SubjectToken))
            {
                throw new CustomTokenExchangeException("subject_token is required and cannot be empty.");
            }

            if (request.SubjectToken != request.SubjectToken.Trim())
            {
                throw new CustomTokenExchangeException("subject_token must not include leading or trailing whitespace.");
            }

            if (request.SubjectToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                throw new CustomTokenExchangeException("subject_token must not include a \"Bearer \" prefix.");
            }

            if (!string.IsNullOrWhiteSpace(request.ActorToken) && string.IsNullOrWhiteSpace(request.ActorTokenType))
            {
                throw new CustomTokenExchangeException("actor_token_type is required when actor_token is provided.");
            }
        }
    }
}
