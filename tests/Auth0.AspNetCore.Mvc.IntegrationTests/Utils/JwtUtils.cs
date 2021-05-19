using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public static class JwtUtils
    {
        public static string GenerateToken(int userId, string issuer, string audience, string org_id = null, string nonce = null)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim("sub", userId.ToString()),
            };

            if (!string.IsNullOrWhiteSpace(org_id))
            {
                claims.Add(new Claim("org_id", org_id));
            }

            if (!string.IsNullOrWhiteSpace(nonce))
            {
                claims.Add(new Claim("nonce", nonce));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                Issuer = issuer,
                Audience = audience,
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
