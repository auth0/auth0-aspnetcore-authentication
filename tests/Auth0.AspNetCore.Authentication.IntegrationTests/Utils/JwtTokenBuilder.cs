using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Utils;

internal class JwtTokenBuilder
{
    private readonly List<Claim> _claims = new List<Claim>();

    private string _audience = null;
    private string _issuer = null;
    private DateTime? _expires = null;
    private SigningCredentials? _signingCredentials = null;
    public JwtTokenBuilder(int identifier)
    {
        _claims.Add(new Claim(ClaimTypes.NameIdentifier, identifier.ToString()));
        _claims.Add(new Claim(JwtRegisteredClaimNames.Sub, identifier.ToString()));
    }
        
    public JwtTokenBuilder WithIssuer(string issuer)
    {
        _issuer = issuer;

        return this;
            
    }
    public JwtTokenBuilder WithAudience(string audience)
    {
        _audience = audience;

        return this;
    }
        
    public JwtTokenBuilder WithExpires(DateTime expires)
    {
        _expires = expires;

        return this;
    }
        
    public JwtTokenBuilder WithClaim(string type, string value)
    {
        _claims.Add(new Claim(type, value));

        return this;
    }

    public JwtTokenBuilder SignWithRs256(string resourceName = "Auth0.AspNetCore.Authentication.IntegrationTests.jwks.json")
    {
        JsonWebKeySet keys = new JsonWebKeySet(GetKeys(resourceName).Result);
        _signingCredentials = new SigningCredentials(keys.Keys[0], SecurityAlgorithms.RsaSha256);

        return this;
    }
        
    public string Build()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
            
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(_claims),
            Expires = _expires ?? DateTime.UtcNow.AddDays(7),
            Issuer = _issuer,
            Audience = _audience,
            SigningCredentials = _signingCredentials ?? CreateRs256Credentials()
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

        
    private static async Task<string> GetKeys(string resourceName = "Auth0.AspNetCore.Authentication.IntegrationTests.jwks.json")
    {
        using (var stream = typeof(Startup).Assembly.GetManifestResourceStream(resourceName))
        using (var reader = new StreamReader(stream))
        {
            var body = await reader.ReadToEndAsync();
            return body;
        }
    }

    private SigningCredentials CreateRs256Credentials()
    {
        JsonWebKeySet keys = new JsonWebKeySet(GetKeys().Result);
        return new SigningCredentials(keys.Keys[0], SecurityAlgorithms.RsaSha256);
    }
}