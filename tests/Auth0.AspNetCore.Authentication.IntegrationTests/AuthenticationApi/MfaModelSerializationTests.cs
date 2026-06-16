using System.Text.Json;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class MfaModelSerializationTests
    {
        [Fact]
        public void MfaChallengeResponse_Deserializes_WireFields()
        {
            var json = "{\"challenge_type\":\"oob\",\"oob_code\":\"abc\",\"binding_method\":\"prompt\"}";

            var result = JsonSerializer.Deserialize<MfaChallengeResponse>(json);

            result.Should().NotBeNull();
            result!.ChallengeType.Should().Be("oob");
            result.OobCode.Should().Be("abc");
            result.BindingMethod.Should().Be("prompt");
        }

        [Fact]
        public void MfaOtpTokenResponse_Deserializes_TokenBaseAndExpiresIn()
        {
            var json = "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"expires_in\":86400}";

            var result = JsonSerializer.Deserialize<MfaOtpTokenResponse>(json);

            result!.AccessToken.Should().Be("at");
            result.TokenType.Should().Be("Bearer");
            result.ExpiresIn.Should().Be(86400);
        }

        [Fact]
        public void MfaOobTokenResponse_Deserializes_ErrorFields()
        {
            var json = "{\"error\":\"authorization_pending\",\"error_description\":\"pending\"}";

            var result = JsonSerializer.Deserialize<MfaOobTokenResponse>(json);

            result!.Error.Should().Be("authorization_pending");
            result.ErrorDescription.Should().Be("pending");
        }

        [Fact]
        public void MfaRecoveryCodeResponse_Deserializes_NewRecoveryCode()
        {
            var json = "{\"access_token\":\"at\",\"expires_in\":3600,\"recovery_code\":\"NEWCODE\"}";

            var result = JsonSerializer.Deserialize<MfaRecoveryCodeResponse>(json);

            result!.AccessToken.Should().Be("at");
            result.RecoveryCode.Should().Be("NEWCODE");
        }

        [Fact]
        public void AssociateMfaAuthenticatorResponse_Deserializes_WireFields()
        {
            var json = "{\"oob_code\":\"oc\",\"binding_method\":\"prompt\",\"authenticator_type\":\"oob\"," +
                       "\"oob_channel\":\"sms\",\"recovery_codes\":[\"r1\"],\"barcode_uri\":\"uri\",\"secret\":\"s\"}";

            var result = JsonSerializer.Deserialize<AssociateMfaAuthenticatorResponse>(json);

            result!.OobCode.Should().Be("oc");
            result.AuthenticatorType.Should().Be("oob");
            result.OobChannel.Should().Be("sms");
            result.RecoveryCodes.Should().ContainSingle().Which.Should().Be("r1");
            result.BarcodeUri.Should().Be("uri");
            result.Secret.Should().Be("s");
        }

        [Fact]
        public void Authenticator_Deserializes_WireFields()
        {
            var json = "{\"id\":\"auth|1\",\"authenticator_type\":\"otp\",\"oob_channel\":null,\"name\":\"My OTP\",\"active\":true}";

            var result = JsonSerializer.Deserialize<Authenticator>(json);

            result!.Id.Should().Be("auth|1");
            result.AuthenticatorType.Should().Be("otp");
            result.Name.Should().Be("My OTP");
            result.Active.Should().BeTrue();
        }
    }
}
