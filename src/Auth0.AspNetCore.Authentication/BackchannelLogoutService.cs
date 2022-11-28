using System;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Authentication
{
    public class BackchannelLogoutService
    {
        public BackchannelLogoutService()
        {

        }

        public virtual async Task ProcessRequestAsync(HttpContext context)
        {
            try
            {
                if (context.Request.Method == "POST")
                {
                    if (context.Request.HasFormContentType)
                    {
                        var logoutToken = context.Request.Form["logout_token"].FirstOrDefault();

                        if (!String.IsNullOrWhiteSpace(logoutToken))
                        {
                            var auth0Options = context.RequestServices.GetRequiredService<IOptionsSnapshot<Auth0WebAppOptions>>().Get(Auth0Constants.AuthenticationScheme);

                            var issuer = $"https://{auth0Options.Domain}/";
                            //var keyInput = "";
                            var audience = auth0Options.ClientId;


                            var claims = ValidateLogoutToken(logoutToken, issuer, audience, "");

                            if (claims != null)
                            {
                                // these are the sub & sid to signout
                                //var sub = user.FindFirst("sub")?.Value;
                                var sidClaimType = "sid"; //replace
                                var sid = claims.FirstOrDefault(c => c.Type == sidClaimType).Value;

                                LogoutTokenStore.Instance.Set($"{issuer}|{sid}", logoutToken);

                                return;
                            }
                        }
                        else
                        {
                            // invalid_request
                            // Missing logout_token
                            context.Response.StatusCode = 400;
                        }
                    }
                }
                else
                {
                    // 405: Method Not Allowed
                    context.Response.StatusCode = 405;
                }
            }
            catch (Exception ex)
            {
                // invalid_request
                // ex.message
                context.Response.StatusCode = 400;
            }

        }

        private IEnumerable<Claim> ValidateLogoutToken(String token, string issuer, string audience, string algorithm)
        {
            var handler = new JwtSecurityTokenHandler();
            var validations = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
            };

            //var jwtSecurityToken = handler.ValidateToken(token, validations, out var tokenSecure);
            var jwtSecurityToken = handler.ReadJwtToken(token);

            return jwtSecurityToken.Claims; 

        }
    }
}

