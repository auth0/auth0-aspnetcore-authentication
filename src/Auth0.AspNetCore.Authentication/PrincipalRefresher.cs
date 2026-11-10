using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    internal static class PrincipalRefresher
    {
        /// <summary>
        /// Rebuilds a <see cref="ClaimsPrincipal"/> from the refreshed <paramref name="idToken"/>,
        /// mirroring the login-time claim mapping. Returns <c>null</c> if the token is malformed,
        /// fails signature/issuer/audience validation (Full mode), or fails the SDK's
        /// business-rule checks; the caller then keeps the existing principal.
        /// </summary>
        public static async Task<ClaimsPrincipal?> RebuildAsync(
            string idToken,
            ClaimsPrincipal currentPrincipal,
            Auth0WebAppOptions options,
            OpenIdConnectOptions oidcOptions,
            RefreshClaimsValidationType validationType,
            IDictionary<string, string?>? properties,
            HttpContext httpContext,
            CancellationToken cancellationToken)
        {
            var handler = new JwtSecurityTokenHandler();
            if (string.IsNullOrEmpty(idToken) || !handler.CanReadToken(idToken))
            {
                return null;
            }

            try
            {
                var configuration = oidcOptions.ConfigurationManager != null
                    ? await oidcOptions.ConfigurationManager.GetConfigurationAsync(cancellationToken)
                    : null;

                // In multiple-custom-domains mode the SDK disables static issuer validation
                // (ValidateIssuer = false) because the real issuer is the per-request resolved
                // domain. Pin the refreshed token to the issuer bound to the session so a request
                // resolving to another domain cannot move the session's issuer (and with it the
                // back-channel logout revocation key) to that domain. The domain resolved for this
                // request is only used for sessions that carry no issuer at all.
                var validateIssuer = oidcOptions.TokenValidationParameters.ValidateIssuer;
                var validIssuer = oidcOptions.TokenValidationParameters.ValidIssuer;

                if (!validateIssuer)
                {
                    var resolvedIssuer = SessionIssuer.Get(currentPrincipal, properties)
                        ?? httpContext.GetResolvedDomain();

                    if (!string.IsNullOrWhiteSpace(resolvedIssuer))
                    {
                        validIssuer = Utils.ToAuthority(resolvedIssuer);
                        validateIssuer = true;
                    }
                }

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = validateIssuer,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidIssuer = validIssuer,
                    ValidAudience = oidcOptions.TokenValidationParameters.ValidAudience,
                    NameClaimType = oidcOptions.TokenValidationParameters.NameClaimType,
                    RoleClaimType = oidcOptions.TokenValidationParameters.RoleClaimType,
                };

                if (configuration != null)
                {
                    tokenValidationParameters.IssuerSigningKeys =
                        oidcOptions.TokenValidationParameters.IssuerSigningKeys?.Concat(configuration.SigningKeys)
                        ?? configuration.SigningKeys;
                }

                if (validationType == RefreshClaimsValidationType.SkipSignature)
                {
                    // SkipSignature trusts the back-channel TLS exchange with the token endpoint,
                    // so we bypass signature verification. We still run the token through the same
                    // SecurityTokenValidator as Full mode so the inbound claim-type mapping matches
                    // the login path (e.g. ClaimTypes.NameIdentifier vs the short "sub" name).
                    tokenValidationParameters.RequireSignedTokens = false;
                    tokenValidationParameters.SignatureValidator = (token, _) => new JwtSecurityToken(token);
                }

                var principal = oidcOptions.SecurityTokenValidator.ValidateToken(idToken, tokenValidationParameters, out _);

                // Both modes run the SDK's business-rule checks (sub, iat, azp, org). The
                // auth_time/MaxAge check is deliberately skipped: a refresh grant does not
                // re-authenticate the user, so auth_time never advances and enforcing MaxAge
                // here would make every refresh fail once the login-freshness window elapses.
                // Passing the auth properties re-applies the login-time organization constraint.
                IdTokenValidator.Validate(options, handler.ReadJwtToken(idToken), properties, validateAuthTime: false);

                return principal;
            }
            catch (System.Exception)
            {
                // Any validation/parse failure degrades gracefully: caller keeps the stale principal.
                return null;
            }
        }
    }
}
