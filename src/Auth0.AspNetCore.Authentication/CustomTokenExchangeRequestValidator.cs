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

            if (request.SubjectToken.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                throw new CustomTokenExchangeException("subject_token must not include a \"Bearer \" prefix.");
            }

            ValidateSubjectTokenType(request.SubjectTokenType);

            var hasActorToken = !string.IsNullOrWhiteSpace(request.ActorToken);
            var hasActorTokenType = !string.IsNullOrWhiteSpace(request.ActorTokenType);

            if (hasActorToken && !hasActorTokenType)
            {
                throw new CustomTokenExchangeException("actor_token_type is required when actor_token is provided.");
            }

            if (hasActorTokenType && !hasActorToken)
            {
                throw new CustomTokenExchangeException("actor_token is required when actor_token_type is provided.");
            }

            if (hasActorToken && !IsValidUri(request.ActorTokenType!))
            {
                throw new CustomTokenExchangeException("actor_token_type must be a valid URI (URL or URN).");
            }
        }

        private static void ValidateSubjectTokenType(string type)
        {
            if (string.IsNullOrWhiteSpace(type) || type.Length < 10)
            {
                throw new CustomTokenExchangeException("subject_token_type must be at least 10 characters.");
            }

            if (type.Length > 100)
            {
                throw new CustomTokenExchangeException("subject_token_type must be at most 100 characters.");
            }

            if (type.StartsWith("urn:ietf:", StringComparison.OrdinalIgnoreCase) ||
                type.StartsWith("urn:auth0:", StringComparison.OrdinalIgnoreCase))
            {
                throw new CustomTokenExchangeException(
                    "subject_token_type must not use the reserved urn:ietf: or urn:auth0: namespaces; use a custom URI.");
            }

            if (!IsValidUri(type))
            {
                throw new CustomTokenExchangeException("subject_token_type must be a valid URI (URL or URN).");
            }
        }

        // A valid absolute URL, or a URN of the form urn:<nid>:<nss>.
        private static bool IsValidUri(string value)
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                return true;
            }

            return System.Text.RegularExpressions.Regex.IsMatch(
                value,
                @"^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }
    }
}
