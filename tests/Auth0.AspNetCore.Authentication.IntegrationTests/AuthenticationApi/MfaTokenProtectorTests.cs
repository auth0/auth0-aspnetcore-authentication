using System;
using Auth0.AspNetCore.Authentication;
using Auth0.AspNetCore.Authentication.AuthenticationApi;
using Auth0.AspNetCore.Authentication.AuthenticationApi.Models;
using FluentAssertions;
using Microsoft.AspNetCore.DataProtection;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.AuthenticationApi
{
    public class MfaTokenProtectorTests
    {
        private static MfaTokenProtector NewProtector(IDataProtectionProvider? provider = null) =>
            new MfaTokenProtector(provider ?? new EphemeralDataProtectionProvider());

        private static MfaTokenContext SampleContext() => new MfaTokenContext
        {
            MfaToken = "raw-mfa-token",
            Audience = "https://api.example.com",
            Scope = "read:items",
            MfaRequirements = new MfaRequirements(),
            ExpiresAtUnix = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()
        };

        [Fact]
        public void Protect_Then_Unprotect_RoundTrips_Context()
        {
            var protector = NewProtector();

            var blob = protector.Protect(SampleContext());
            var recovered = protector.Unprotect(blob);

            blob.Should().NotBe("raw-mfa-token");
            recovered.MfaToken.Should().Be("raw-mfa-token");
            recovered.Audience.Should().Be("https://api.example.com");
            recovered.Scope.Should().Be("read:items");
        }

        [Fact]
        public void Protect_SetsFiveMinuteExpiry_WhenNotPreset()
        {
            var protector = NewProtector();
            var ctx = SampleContext();
            ctx.ExpiresAtUnix = 0; // ask the protector to stamp it

            var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var blob = protector.Protect(ctx);
            var recovered = protector.Unprotect(blob);

            recovered.ExpiresAtUnix.Should().BeInRange(before + 290, before + 310);
        }

        [Fact]
        public void Unprotect_Tampered_Throws_MfaTokenInvalid()
        {
            var protector = NewProtector();
            var blob = protector.Protect(SampleContext());

            var tampered = blob.Substring(0, blob.Length - 2) + (blob.EndsWith("A") ? "B" : "A");

            Action act = () => protector.Unprotect(tampered);
            act.Should().Throw<MfaTokenInvalidException>();
        }

        [Fact]
        public void Unprotect_Garbage_Throws_MfaTokenInvalid()
        {
            var protector = NewProtector();

            Action act = () => protector.Unprotect("not-a-real-blob");
            act.Should().Throw<MfaTokenInvalidException>();
        }

        [Fact]
        public void Unprotect_WrongKey_Throws_MfaTokenInvalid()
        {
            var blob = NewProtector().Protect(SampleContext());

            // A different provider => different key ring => MAC fails.
            Action act = () => NewProtector().Unprotect(blob);
            act.Should().Throw<MfaTokenInvalidException>();
        }

        [Fact]
        public void Unprotect_Expired_Throws_MfaTokenExpired()
        {
            var protector = NewProtector();
            var ctx = SampleContext();
            ctx.ExpiresAtUnix = DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds();

            var blob = protector.Protect(ctx);

            Action act = () => protector.Unprotect(blob);
            act.Should().Throw<MfaTokenExpiredException>();
        }
    }
}
