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

        // The cases above are rejected by the 3-segment check before any decoding. These are JWT-shaped
        // but carry an undecodable payload, so they exercise the decoder throwing and the catch that
        // turns that into null - the contract relied on by using Base64UrlEncoder.DecodeBytes.
        [Theory]
        [InlineData("header.not!valid!base64.sig")]
        [InlineData("header.a.sig")]              // 1 char - never a valid base64url length
        [InlineData("header.====.sig")]
        [InlineData("header..sig")]               // empty payload decodes to zero bytes, then JSON fails
        public void Returns_Null_When_Payload_Cannot_Be_Decoded(string jwt)
        {
            ActClaimReader.TryRead(jwt).Should().BeNull();
        }

        // Base64url payloads need 0, 1 or 2 '=' of padding restored depending on length % 4. Each case
        // below lands on a different remainder, so all padding branches are covered.
        [Theory]
        [InlineData("{\"act\":{\"sub\":\"a\"}}", "a")]
        [InlineData("{\"act\":{\"sub\":\"ab\"}}", "ab")]
        [InlineData("{\"act\":{\"sub\":\"abc\"}}", "abc")]
        [InlineData("{\"act\":{\"sub\":\"abcd\"}}", "abcd")]
        public void Decodes_Payloads_Of_Every_Padding_Length(string payloadJson, string expectedSub)
        {
            var jwt = JwtWithPayload(payloadJson);

            ActClaimReader.TryRead(jwt)!.Sub.Should().Be(expectedSub);
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
