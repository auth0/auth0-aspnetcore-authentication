using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace Auth0.AspNetCore.Authentication
{
    /// <summary>
    /// Validates the organization claim on the ID token returned from a Custom Token Exchange
    /// against the requested organization. An <c>org_</c>-prefixed value is matched exactly against
    /// the <c>org_id</c> claim; any other value is matched case-insensitively against <c>org_name</c>.
    /// </summary>
    internal static class OrganizationClaimValidator
    {
        public static void Validate(string? idToken, string organization)
        {
            // No ID token means there is no organization claim to validate (e.g. an exchange that
            // returned only an access token). Nothing to check.
            if (string.IsNullOrWhiteSpace(organization) || string.IsNullOrEmpty(idToken))
            {
                return;
            }

            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(idToken))
            {
                throw new CustomTokenExchangeException(
                    "organization was requested but the returned ID token could not be read to validate the organization claim.");
            }

            var token = handler.ReadJwtToken(idToken);

            var organizationClaim = organization.StartsWith("org_", StringComparison.Ordinal) ? "org_id" : "org_name";
            var claimValue = token.Claims.FirstOrDefault(claim => claim.Type == organizationClaim)?.Value;

            if (string.IsNullOrWhiteSpace(claimValue))
            {
                throw new CustomTokenExchangeException(
                    $"Organization claim ({organizationClaim}) must be present in the returned ID token.");
            }

            var matches = organizationClaim == "org_name"
                ? string.Equals(claimValue, organization, StringComparison.OrdinalIgnoreCase)
                : string.Equals(claimValue, organization, StringComparison.Ordinal);

            if (!matches)
            {
                throw new CustomTokenExchangeException(
                    $"Organization claim ({organizationClaim}) mismatch in the returned ID token; expected \"{organization}\", found \"{claimValue}\".");
            }
        }
    }
}
