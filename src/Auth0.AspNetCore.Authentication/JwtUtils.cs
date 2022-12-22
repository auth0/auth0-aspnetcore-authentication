using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Runtime;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth0.AspNetCore.Authentication
{
    interface ISigningCredentialsFactory: IDisposable
    {
        public string SecurityAlgorithm { get; }

        SigningCredentials GenerateSigningCredentials();
    }

    class RSASigningCredentialsFactory : ISigningCredentialsFactory
    {
        private RSACryptoServiceProvider _provider = new RSACryptoServiceProvider();

        private readonly string privateKeyPem;

        public string SecurityAlgorithm => SecurityAlgorithms.RsaSha256;

        public RSASigningCredentialsFactory(string privateKeyPem)
        {
            this.privateKeyPem = privateKeyPem;
        }

        public SigningCredentials GenerateSigningCredentials()
        {
            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

            _provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);

            return new SigningCredentials(new RsaSecurityKey(_provider), SecurityAlgorithm); ;
        }

        public void Dispose()
        {
            if (_provider != null)
            {
                _provider.Dispose();
            }
        }
    }

    class HmacSigningCredentialsFactory : ISigningCredentialsFactory
    {
        private readonly string privateKeyPem;

        public string SecurityAlgorithm => SecurityAlgorithms.HmacSha256;

        public HmacSigningCredentialsFactory(string privateKeyPem)
        {
            this.privateKeyPem = privateKeyPem;
        }

        public SigningCredentials GenerateSigningCredentials()
        {
            return new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(privateKeyPem)), SecurityAlgorithm);
        }

        public void Dispose()
        {
        }
    }

    class PSSigningCredentialsFactory : ISigningCredentialsFactory
    {
        private RSACryptoServiceProvider _provider = new RSACryptoServiceProvider(2048);

        private readonly string privateKeyPem;

        public string SecurityAlgorithm => SecurityAlgorithms.RsaSsaPssSha256;

        public PSSigningCredentialsFactory(string privateKeyPem)
        {
            this.privateKeyPem = privateKeyPem;
        }

        public SigningCredentials GenerateSigningCredentials()
        {
            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);

            _provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);

            return new SigningCredentials(new RsaSecurityKey(_provider), SecurityAlgorithm);
        }

        public void Dispose()
        {
            if (_provider != null)
            {
                _provider.Dispose();
            }
        }
    }

    class JwtTokenFactory : IDisposable
    {
        private ISigningCredentialsFactory _factory;
        private readonly string privateKeyPem;

        // Should take IssuerSigningKey instead
        public JwtTokenFactory(string privateKeyPem, string privateKeyType)
        {
            this.privateKeyPem = privateKeyPem;
            this._factory = CreateSigningCredentialsFactory(privateKeyPem, privateKeyType);
        }


        public string GenerateToken(JwtCAPayload payload)
        {
            var signingCredentials = _factory.GenerateSigningCredentials();

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = CreateSecurityTokenDescriptor(payload, signingCredentials);

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        public void Dispose()
        {
            if (_factory != null)
            {
                _factory.Dispose();
            }
        }

        private ISigningCredentialsFactory CreateSigningCredentialsFactory(string privateKey, string privateKeyType)
        {
            switch (privateKeyType)
            {
                case SecurityAlgorithms.HmacSha256:
                    return new HmacSigningCredentialsFactory(privateKey);
                case SecurityAlgorithms.RsaSsaPssSha256:
                    return new PSSigningCredentialsFactory(privateKey);
                default:
                    return new RSASigningCredentialsFactory(privateKey);
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

    class JwtTokenFactory2
    {
        private readonly SecurityKey securityKey;
        private readonly string algorithm;

        // Should take IssuerSigningKey instead
        public JwtTokenFactory2(SecurityKey securityKey, string algorithm)
        {
            this.securityKey = securityKey;
            this.algorithm = algorithm;
        }


        public string GenerateToken(JwtCAPayload payload)
        {
            var signingCredentials = CreateSigningCredentials();

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = CreateSecurityTokenDescriptor(payload, signingCredentials);

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        private SigningCredentials CreateSigningCredentials()
        {
            return new SigningCredentials(securityKey, algorithm);
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

    class JwtCAPayload
    {
        public string ClientId { get; set; }
        public string Audience { get; set; }
    }
}
