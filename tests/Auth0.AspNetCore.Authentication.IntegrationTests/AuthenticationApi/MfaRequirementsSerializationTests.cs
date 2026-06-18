using System.Text.Json;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class MfaRequirementsSerializationTests
    {
        [Fact]
        public void MfaRequirements_Deserializes_ChallengeArray()
        {
            var json = "{\"challenge\":[{\"type\":\"otp\"},{\"type\":\"oob\",\"oob_channels\":[\"sms\"],\"authenticator_id\":\"recovery-code|dev_1\"}]}";

            var result = JsonSerializer.Deserialize<MfaRequirements>(json);

            result.Should().NotBeNull();
            result!.Challenge.Should().HaveCount(2);
            result.Challenge![0].Type.Should().Be("otp");
            result.Challenge[1].Type.Should().Be("oob");
            result.Challenge[1].OobChannels.Should().ContainSingle().Which.Should().Be("sms");
            result.Challenge[1].AuthenticatorId.Should().Be("recovery-code|dev_1");
        }

        [Fact]
        public void MfaRequirements_Ignores_UnknownFields()
        {
            var json = "{\"challenge\":[{\"type\":\"otp\",\"future_field\":123}],\"another_unknown\":true}";

            var result = JsonSerializer.Deserialize<MfaRequirements>(json);

            result!.Challenge.Should().ContainSingle();
            result.Challenge![0].Type.Should().Be("otp");
        }
    }
}
