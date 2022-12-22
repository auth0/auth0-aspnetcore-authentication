using System;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using System.Net;
using System.Threading.Tasks;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using FluentAssertions;
using System.Security.Cryptography;
using System.Text;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class JwtUtilsTests
    {
        public JwtUtilsTests()
        {
        }

        [Fact]
        public async Task Should_generate_jwt_token_using_HS265()
        {
            var hmac = new HMACSHA256();
            var key = Convert.ToBase64String(hmac.Key);
            using var factory = new JwtTokenFactory(key, SecurityAlgorithms.HmacSha256);

            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });

            token.Should().NotBeNull();
        }

        [Fact]
        public async Task Should_generate_jwt_token_using_HS265_signingKey()
        {
            var hmac = new HMACSHA256();
            var key = Convert.ToBase64String(hmac.Key);
            var factory = new JwtTokenFactory2(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256);

            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });

            token.Should().NotBeNull();
        }


        [Fact]
        public async Task Should_generate_jwt_token_using_RS265()
        {
            using var factory = new JwtTokenFactory(@"MIIBOwIBAAJBAKeq9UUjOc+ADri/0Hj945jcUtEKwx3y4RmuYffCm5n29NOiXGcG
f4zj+DR3Lh6pMBZON/l+EcR9QdWEkuF1wW0CAwEAAQJAWeFvcgycJPwE6E0LOJEB
vSP+0Ujvp9JXkSjGI8cTGslF0RWbAdqeE1KeAibiY7F0fixOo0W/+BV5fYr5kMmg
EQIhANeDgEoVFLHPmr3RV/eiMHJmi1Op6AElN81TWtz8g8t3AiEAxypzMAZpinuN
1LdSXLzb5f/39ofsyI6PNxo4dyvWSzsCIQDJYUikcPRofpyS2KZBcF2i2K1CXVa8
k0GEbGpQaujgWwIgbt5AlOFc6wvwXhNWs+0l9BjTbdcohlRlgOUFvcEXX3UCIQDP
NUSmXiyu/PaoELrp7azaSm++087wVnVdHOhPezUStA==", SecurityAlgorithms.RsaSha256);

            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });

            token.Should().NotBeNull();
        }

        [Fact]
        public async Task Should_generate_jwt_token_using_RS265_signingKey()
        { 
            var privateKeyPem = @"MIIBOwIBAAJBAKeq9UUjOc+ADri/0Hj945jcUtEKwx3y4RmuYffCm5n29NOiXGcG
f4zj+DR3Lh6pMBZON/l+EcR9QdWEkuF1wW0CAwEAAQJAWeFvcgycJPwE6E0LOJEB
vSP+0Ujvp9JXkSjGI8cTGslF0RWbAdqeE1KeAibiY7F0fixOo0W/+BV5fYr5kMmg
EQIhANeDgEoVFLHPmr3RV/eiMHJmi1Op6AElN81TWtz8g8t3AiEAxypzMAZpinuN
1LdSXLzb5f/39ofsyI6PNxo4dyvWSzsCIQDJYUikcPRofpyS2KZBcF2i2K1CXVa8
k0GEbGpQaujgWwIgbt5AlOFc6wvwXhNWs+0l9BjTbdcohlRlgOUFvcEXX3UCIQDP
NUSmXiyu/PaoELrp7azaSm++087wVnVdHOhPezUStA==";

            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);
            using var provider = new RSACryptoServiceProvider();
            provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);

            var factory = new JwtTokenFactory2(new RsaSecurityKey(provider), SecurityAlgorithms.RsaSha256);

            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });

            token.Should().NotBeNull();
        }

        [Fact]
        public async Task Should_generate_jwt_token_using_PS265()
        {
            using var factory = new JwtTokenFactory(@"MIIEogIBAAKCAQEAtqORT+cyjOp9fcDLnrtlBffX8Au7OkEVpSXMnULBeuAtAynU
8zc5u5B65+tRkX/4Gwul3GYO8JIfu4g56rcLn/QRXwCf2Pa1LqKBdoU2xxSEV0xl
i+fqO1VZn4tF9u67rUnNXYs3dok/CBjkqOS1OK4tVzFqCwD1GSv5NeMf4qaYtIXh
4JLPGo03Z2FTq3NHYZ3NYMtmT9pgxa+/Yul2ptNemdZ8ZFdagcUPnpCFo2DpwQMv
JxZ5sWJ0YSuwe2mQWJkQKIvYGz2nBRZoBttGODC90CRhVHM6rIEU5TqRyy9thrvv
zAYa5y3XPrc+6FMZJsOHR6wKKN2ZCnqQhNv6AwIDAQABAoIBAFGFCKMlisajE4hB
uaEL+7eCPHwEgHkr+8FO8dlvpnR2AyFaVpaIm9hAUNubiTjsaY2I0WtikmCGmGtY
DqHZOfMXOXmyCacJ1y0Nk8OXCjAp1Dgy/VBJH5+EJRC1VXE2dcaPHn8WWJcsA1pV
4hoQm2LFO6+jerWWo8+sdPu8eMrs2DGm/I2xJgcwCVNeMm1txoggf6rEnmiM/bp5
F8q+nsQ5aZWM/p8ARYUpWTNPhoY0HFLZiP1fJiw+n5QcTKBC9HAheCAeBWRhy9gh
0YoqA1h+clxfiqV/U1IWURDajeyCRkn/NSRo5cZoBWB7U1EcETz/lJ8zFqPaoH9F
Uk8upQECgYEA34F4brYBqaAMGuUZdYuwignHB2DtxYkyQj7e8LsKXjzaYBOKPHuu
J05TyotifEHQk3aHoBrEGR/G8kxcUkxXTYays7OeEPVE1plvAt0YMC9U0r0Nm3bN
JERUuVp1ESl3+cOqkb/S1zUsTStCbNfaaGO00gsz8PLt0Kv2vi+K1CMCgYEA0TEZ
cAt3dE83+qDPbkhdtlNC+rCt54NhUR1+EWD/dnxQdXMXh2Q1FHzuJq8OThVDKVEw
BFQMVXoleAusq5zRvRHE9oo6kXZ+QXBCmQrbBF6bwxKm+Mppw8ew1ApfS5IRLvj2
1xovUxqooCkVgCVpF5nHLRuiyjYH1C9GlP+CMKECgYAbHMuNMor1FrMhOBVkivN5
a0I3hOyS/9eW7aWBsk7Jq7wZ14T3XVF89yV29n2V8S3qFYDSTSzol1A86EJywUv9
3Y8j+W/9QqN9HNO4lzVt8u/pOIHEEB9GfPuCGJUG5e7l33R7hbd/37VmDw9ZwL1/
2EiBClbcrbtnitS9sWq33QKBgCirN/vNbuLAx+xEuS8CiJ16oGnmUVjR9Oh1KF4u
kluxnV7ICkn7FEqwYwhIPiq1/YGZ1BDzWhaAEaq98krGyQvN2ZHom6xN8gu8zGW+
c4fs8LFC/g0eJOO3/curXI1vj0Gniy2UXKD2bNP+SLzKCR1aexts5QAU8v6wVjN/
XQshAoGARCG4nHPKASNzGhVixI3EfKuQ/S/joITydsTDNBZgKlBygrNQ9VbtQG5I
P6oOIeHtHkEOXOGN12om/bJuAqP27LAZu4eII4FtlJw9k5MoFr3vKIhtR5C7SNzw
eqjAXkLGnuZaJmARm43XwsX+gIBBOlfD52nWKSjL7+PLVyDMRdA=", SecurityAlgorithms.RsaSsaPssSha256);


            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });


            token.Should().NotBeNull();
        }

        [Fact]
        public async Task Should_generate_jwt_token_using_PS265_signingKey()
        {
            var privateKeyPem = @"MIIEogIBAAKCAQEAtqORT+cyjOp9fcDLnrtlBffX8Au7OkEVpSXMnULBeuAtAynU
8zc5u5B65+tRkX/4Gwul3GYO8JIfu4g56rcLn/QRXwCf2Pa1LqKBdoU2xxSEV0xl
i+fqO1VZn4tF9u67rUnNXYs3dok/CBjkqOS1OK4tVzFqCwD1GSv5NeMf4qaYtIXh
4JLPGo03Z2FTq3NHYZ3NYMtmT9pgxa+/Yul2ptNemdZ8ZFdagcUPnpCFo2DpwQMv
JxZ5sWJ0YSuwe2mQWJkQKIvYGz2nBRZoBttGODC90CRhVHM6rIEU5TqRyy9thrvv
zAYa5y3XPrc+6FMZJsOHR6wKKN2ZCnqQhNv6AwIDAQABAoIBAFGFCKMlisajE4hB
uaEL+7eCPHwEgHkr+8FO8dlvpnR2AyFaVpaIm9hAUNubiTjsaY2I0WtikmCGmGtY
DqHZOfMXOXmyCacJ1y0Nk8OXCjAp1Dgy/VBJH5+EJRC1VXE2dcaPHn8WWJcsA1pV
4hoQm2LFO6+jerWWo8+sdPu8eMrs2DGm/I2xJgcwCVNeMm1txoggf6rEnmiM/bp5
F8q+nsQ5aZWM/p8ARYUpWTNPhoY0HFLZiP1fJiw+n5QcTKBC9HAheCAeBWRhy9gh
0YoqA1h+clxfiqV/U1IWURDajeyCRkn/NSRo5cZoBWB7U1EcETz/lJ8zFqPaoH9F
Uk8upQECgYEA34F4brYBqaAMGuUZdYuwignHB2DtxYkyQj7e8LsKXjzaYBOKPHuu
J05TyotifEHQk3aHoBrEGR/G8kxcUkxXTYays7OeEPVE1plvAt0YMC9U0r0Nm3bN
JERUuVp1ESl3+cOqkb/S1zUsTStCbNfaaGO00gsz8PLt0Kv2vi+K1CMCgYEA0TEZ
cAt3dE83+qDPbkhdtlNC+rCt54NhUR1+EWD/dnxQdXMXh2Q1FHzuJq8OThVDKVEw
BFQMVXoleAusq5zRvRHE9oo6kXZ+QXBCmQrbBF6bwxKm+Mppw8ew1ApfS5IRLvj2
1xovUxqooCkVgCVpF5nHLRuiyjYH1C9GlP+CMKECgYAbHMuNMor1FrMhOBVkivN5
a0I3hOyS/9eW7aWBsk7Jq7wZ14T3XVF89yV29n2V8S3qFYDSTSzol1A86EJywUv9
3Y8j+W/9QqN9HNO4lzVt8u/pOIHEEB9GfPuCGJUG5e7l33R7hbd/37VmDw9ZwL1/
2EiBClbcrbtnitS9sWq33QKBgCirN/vNbuLAx+xEuS8CiJ16oGnmUVjR9Oh1KF4u
kluxnV7ICkn7FEqwYwhIPiq1/YGZ1BDzWhaAEaq98krGyQvN2ZHom6xN8gu8zGW+
c4fs8LFC/g0eJOO3/curXI1vj0Gniy2UXKD2bNP+SLzKCR1aexts5QAU8v6wVjN/
XQshAoGARCG4nHPKASNzGhVixI3EfKuQ/S/joITydsTDNBZgKlBygrNQ9VbtQG5I
P6oOIeHtHkEOXOGN12om/bJuAqP27LAZu4eII4FtlJw9k5MoFr3vKIhtR5C7SNzw
eqjAXkLGnuZaJmARm43XwsX+gIBBOlfD52nWKSjL7+PLVyDMRdA=";

            byte[] privateKeyRaw = Convert.FromBase64String(privateKeyPem);
            using var provider = new RSACryptoServiceProvider(2048);
            provider.ImportRSAPrivateKey(new ReadOnlySpan<byte>(privateKeyRaw), out _);

            var factory = new JwtTokenFactory2(new RsaSecurityKey(provider), SecurityAlgorithms.RsaSha256);

            var token = factory.GenerateToken(new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });

            token.Should().NotBeNull();
        }
    }
}

