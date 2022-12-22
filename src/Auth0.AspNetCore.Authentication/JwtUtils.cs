using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth0.AspNetCore.Authentication
{
    class MyCustomCryptoProviderFactory : CryptoProviderFactory
    {
        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return base.CreateForSigning(key, algorithm);
        }
    }
    class JwtCAPayload
    {
        public string ClientId { get; set; }
        public string Audience { get; set; }
    }
    internal static class JwtUtils
    {
        public static string GenerateJwtToken(string privateKeyPem, JwtCAPayload payload)
        {
            //string privateKeyPem = File.ReadAllText("~/../../../../privateKey.pem");

            // keeping only the payload of the key 
            //privateKeyPem = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "");
            //privateKeyPem = privateKeyPem.Replace("-----END RSA PRIVATE KEY-----", "");

            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

            var signingCredentials = CreateSigningCredentials(privateKeyRaw);

            //using (var provider = new RSACryptoServiceProvider())
            //{
            //provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            //var rsaSecurityKey = new RsaSecurityKey(provider);


            var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = CreateSecurityTokenDescriptor(payload, signingCredentials);

                var token = tokenHandler.CreateToken(tokenDescriptor);

                return tokenHandler.WriteToken(token);
            //}


        }

        private static SecurityKey CreateSecurityKey(byte[] privateKeyRaw)
        {
            using (var provider = new RSACryptoServiceProvider())
            {
                provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
                return new RsaSecurityKey(provider);
            }
        }

        private static SigningCredentials CreateSigningCredentials(byte[] privateKeyRaw)
        {
            using var provider = new RSACryptoServiceProvider();
            
            provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);
            return new SigningCredentials(new RsaSecurityKey(provider), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            
        }

        private static SecurityTokenDescriptor CreateSecurityTokenDescriptor(JwtCAPayload payload, SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                new Claim(JwtRegisteredClaimNames.Sub, payload.ClientId),
                }),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddSeconds(180),
                Issuer = payload.ClientId,
                Audience = payload.Audience,
                Claims = new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Jti, Guid.NewGuid() },
            },

                SigningCredentials = signingCredentials
            };
        }
    }
}
