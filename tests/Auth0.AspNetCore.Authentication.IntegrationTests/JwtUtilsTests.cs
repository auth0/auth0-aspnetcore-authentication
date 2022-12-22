using System;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class JwtUtilsTests
    {
        public JwtUtilsTests()
        {
        }

        [Fact]
        public async Task Should_generate_jwt_token()
        {
            var token = JwtUtils.GenerateJwtToken(@"MIIBOwIBAAJBAKeq9UUjOc+ADri/0Hj945jcUtEKwx3y4RmuYffCm5n29NOiXGcG
f4zj+DR3Lh6pMBZON/l+EcR9QdWEkuF1wW0CAwEAAQJAWeFvcgycJPwE6E0LOJEB
vSP+0Ujvp9JXkSjGI8cTGslF0RWbAdqeE1KeAibiY7F0fixOo0W/+BV5fYr5kMmg
EQIhANeDgEoVFLHPmr3RV/eiMHJmi1Op6AElN81TWtz8g8t3AiEAxypzMAZpinuN
1LdSXLzb5f/39ofsyI6PNxo4dyvWSzsCIQDJYUikcPRofpyS2KZBcF2i2K1CXVa8
k0GEbGpQaujgWwIgbt5AlOFc6wvwXhNWs+0l9BjTbdcohlRlgOUFvcEXX3UCIQDP
NUSmXiyu/PaoELrp7azaSm++087wVnVdHOhPezUStA==", new JwtCAPayload
            {
                Audience = "audience",
                ClientId = "client_id"
            });
        }
    }
}

