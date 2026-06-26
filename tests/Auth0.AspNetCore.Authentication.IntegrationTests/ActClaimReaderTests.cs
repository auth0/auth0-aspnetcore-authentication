using System;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class ActClaimReaderTests
    {
        // Builds a JWT-shaped string (header.payload.signature) with the given JSON payload.
        private static string JwtWithPayload(string payloadJson)
        {
            string B64Url(string s)
            {
                var bytes = Encoding.UTF8.GetBytes(s);
                return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
            return $"{B64Url("{\"alg\":\"RS256\"}")}.{B64Url(payloadJson)}.signature";
        }

        [Fact]
        public void Returns_Null_For_Null_Or_Empty()
        {
            ActClaimReader.TryRead(null).Should().BeNull();
            ActClaimReader.TryRead("").Should().BeNull();
        }

        [Fact]
        public void Returns_Null_For_Malformed_Jwt()
        {
            ActClaimReader.TryRead("not-a-jwt").Should().BeNull();
            ActClaimReader.TryRead("only.two").Should().BeNull();
        }

        [Fact]
        public void Returns_Null_When_No_Act_Claim()
        {
            var jwt = JwtWithPayload("{\"sub\":\"auth0|user123\"}");
            ActClaimReader.TryRead(jwt).Should().BeNull();
        }

        [Fact]
        public void Reads_A_Single_Level_Act_Claim()
        {
            var jwt = JwtWithPayload("{\"sub\":\"auth0|user123\",\"act\":{\"sub\":\"mcp_client_id\"}}");
            var act = ActClaimReader.TryRead(jwt);
            act.Should().NotBeNull();
            act!.Sub.Should().Be("mcp_client_id");
            act.Act.Should().BeNull();
        }

        [Fact]
        public void Reads_A_Nested_Delegation_Chain()
        {
            var jwt = JwtWithPayload(
                "{\"sub\":\"auth0|user123\",\"act\":{\"sub\":\"mcp2\",\"act\":{\"sub\":\"mcp1\"}}}");
            var act = ActClaimReader.TryRead(jwt);
            act.Should().NotBeNull();
            act!.Sub.Should().Be("mcp2");
            act.Act.Should().NotBeNull();
            act.Act!.Sub.Should().Be("mcp1");
        }
    }
}
