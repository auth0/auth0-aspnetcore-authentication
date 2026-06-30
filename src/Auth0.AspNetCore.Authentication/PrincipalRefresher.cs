using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
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
            CancellationToken cancellationToken)
        {
            var handler = new JwtSecurityTokenHandler();
            if (string.IsNullOrEmpty(idToken) || !handler.CanReadToken(idToken))
            {
                return null;
            }

            try
            {
                ClaimsPrincipal principal;

                if (validationType == RefreshClaimsValidationType.Full)
                {
                    var configuration = oidcOptions.ConfigurationManager != null
                        ? await oidcOptions.ConfigurationManager.GetConfigurationAsync(cancellationToken)
                        : null;

                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        RequireExpirationTime = true,
                        ValidIssuer = oidcOptions.TokenValidationParameters.ValidIssuer,
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

                    principal = oidcOptions.SecurityTokenValidator.ValidateToken(idToken, tokenValidationParameters, out _);
                }
                else
                {
                    // SkipSignature: parse the token and project its claims onto a fresh identity
                    // that mirrors the login-time name/role mapping, without verifying the signature.
                    var jwt = handler.ReadJwtToken(idToken);
                    var identity = new ClaimsIdentity(
                        jwt.Claims,
                        currentPrincipal.Identity?.AuthenticationType,
                        oidcOptions.TokenValidationParameters.NameClaimType,
                        oidcOptions.TokenValidationParameters.RoleClaimType);
                    principal = new ClaimsPrincipal(identity);
                }

                // Both modes run the SDK's business-rule checks (sub, iat, azp, org, auth_time).
                // Passing the auth properties re-applies the login-time organization constraint.
                IdTokenValidator.Validate(options, handler.ReadJwtToken(idToken), properties);

                return principal;
            }
            catch (Exception)
            {
                // Any validation/parse failure degrades gracefully: caller keeps the stale principal.
                return null;
            }
        }
    }
}
