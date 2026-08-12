using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class CnfClaimReaderTests
    {
        private const string Header = "eyJhbGciOiJSUzI1NiJ9";
        private const string PayloadWithCnf = "eyJjbmYiOnsieDV0I1MyNTYiOiJhYmMifX0";
        private const string PayloadNoCnf = "eyJzdWIiOiJ1MSJ9";

        [Fact]
        public void Returns_True_When_Cnf_Thumbprint_Present()
        {
            var jwt = $"{Header}.{PayloadWithCnf}.sig";

            CnfClaimReader.HasThumbprintConfirmation(jwt).Should().Be(true);
        }

        [Fact]
        public void Returns_False_When_Jwt_Has_No_Cnf()
        {
            var jwt = $"{Header}.{PayloadNoCnf}.sig";

            CnfClaimReader.HasThumbprintConfirmation(jwt).Should().Be(false);
        }

        [Fact]
        public void Returns_Null_For_Opaque_Token()
        {
            CnfClaimReader.HasThumbprintConfirmation("opaque-access-token").Should().BeNull();
        }

        [Fact]
        public void Returns_Null_For_Null_Or_Empty()
        {
            CnfClaimReader.HasThumbprintConfirmation(null).Should().BeNull();
            CnfClaimReader.HasThumbprintConfirmation("").Should().BeNull();
        }
    }
}
