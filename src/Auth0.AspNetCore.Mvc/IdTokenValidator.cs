using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Auth0.AspNetCore.Mvc.IntegrationTests")]
namespace Auth0.AspNetCore.Mvc
{
    internal static class IdTokenValidator
    {
        public static void Validate(Auth0WebAppOptions auth0Options, JwtSecurityToken token, IDictionary<string, string?>? properties = null)
        {
            var organization = properties != null && properties.ContainsKey(Auth0AuthenticationParameters.Organization) ? properties[Auth0AuthenticationParameters.Organization] : null;

            if (!string.IsNullOrWhiteSpace(organization))
            {
                var organizationClaimValue = token.Claims.SingleOrDefault(claim => claim.Type == "org_id")?.Value;

                if (string.IsNullOrWhiteSpace(organizationClaimValue))
                {
                    throw new IdTokenValidationException("Organization claim must be a string present in the ID token.");
                }
                else if (organizationClaimValue != organization)
                {
                    throw new IdTokenValidationException($"Organization claim mismatch in the ID token; expected \"{organization}\", found \"{organizationClaimValue}\".");
                }
            }

            var sub = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sub)?.Value;

            if (sub == null)
            {
                throw new IdTokenValidationException("Subject (sub) claim must be a string present in the ID token.");
            }

            var iat = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Iat)?.Value;

            if (iat == null)
            {
                throw new IdTokenValidationException("Issued At (iat) claim must be an integer present in the ID token.");
            }

            if (token.Audiences.Count() > 1)
            {
                if (string.IsNullOrWhiteSpace(token.Payload.Azp))
                {
                    throw new IdTokenValidationException("Authorized Party (azp) claim must be a string present in the ID token when Audiences (aud) claim has multiple values.");

                }
                else if (token.Payload.Azp != auth0Options.ClientId)
                {
                    throw new IdTokenValidationException($"Authorized Party (azp) claim mismatch in the ID token; expected \"{auth0Options.ClientId}\", found \"{token.Payload.Azp}\".");
                }
            }

            if (auth0Options.MaxAge.HasValue)
            {
                var authTimeRaw = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.AuthTime)?.Value;
                long? authTime = !string.IsNullOrWhiteSpace(authTimeRaw) ? (long?)Convert.ToDouble(authTimeRaw, CultureInfo.InvariantCulture) : null;

                if (!authTime.HasValue)
                {
                    throw new IdTokenValidationException("Authentication Time (auth_time) claim must be an integer present in the ID token when MaxAge specified.");
                }
                else
                {
                    var authValidUntil = (long)(authTime + auth0Options.MaxAge.Value.TotalSeconds);
                    var epochNow = EpochTime.GetIntDate(DateTime.Now);

                    if (epochNow > authValidUntil)
                    {
                        throw new IdTokenValidationException($"Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time ({epochNow}) is after last auth at {authValidUntil}.");
                    }
                }
            }
        }
    }
}
