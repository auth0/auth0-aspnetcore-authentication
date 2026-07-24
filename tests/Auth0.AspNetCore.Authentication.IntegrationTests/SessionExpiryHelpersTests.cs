using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class SessionExpiryHelpersTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("not-a-number")]
        public void TryParseCeiling_ReturnsFalse_ForMissingOrMalformed(string? raw)
        {
            SessionExpiryHelpers.TryParseCeiling(raw, out var seconds).Should().BeFalse();
            seconds.Should().Be(0);
        }

        [Theory]
        [InlineData("1712345678", 1712345678L)]
        [InlineData("1712345678.0", 1712345678L)]
        public void TryParseCeiling_ParsesIntegerSeconds(string raw, long expected)
        {
            SessionExpiryHelpers.TryParseCeiling(raw, out var seconds).Should().BeTrue();
            seconds.Should().Be(expected);
        }

        [Fact]
        public void IsExpired_IsFalse_WellBeforeCeiling()
        {
            var ceiling = 1_000_000L;
            // A minute before the ceiling (beyond the 30s leeway) is not expired.
            SessionExpiryHelpers.IsExpired(ceiling, ceiling - 60).Should().BeFalse();
        }

        [Fact]
        public void IsExpired_AppliesNegativeLeeway_ExpiresBeforeWallClockCeiling()
        {
            var ceiling = 1_000_000L;
            var leeway = Auth0Constants.SessionExpiryLeewaySeconds;

            // Exactly at (ceiling - leeway) the session is already treated as expired (>=),
            // i.e. expiry fires slightly before the wall-clock ceiling, never after.
            SessionExpiryHelpers.IsExpired(ceiling, ceiling - leeway).Should().BeTrue();
            // One second inside the leeway window is still live.
            SessionExpiryHelpers.IsExpired(ceiling, ceiling - leeway - 1).Should().BeFalse();
        }

        [Fact]
        public void IsExpired_IsTrue_AtAndAfterCeiling()
        {
            var ceiling = 1_000_000L;
            SessionExpiryHelpers.IsExpired(ceiling, ceiling).Should().BeTrue();
            SessionExpiryHelpers.IsExpired(ceiling, ceiling + 3600).Should().BeTrue();
        }

        [Fact]
        public void IsSessionExpired_NoPersistedCeiling_IsNeverExpired()
        {
            // A session created before this feature has no persisted ceiling: it must never be
            // treated as expired, regardless of how far "now" has advanced.
            var properties = new AuthenticationProperties();

            SessionExpiryHelpers.IsSessionExpired(properties, long.MaxValue).Should().BeFalse();
        }

        [Fact]
        public void IsSessionExpired_MalformedPersistedCeiling_IsNeverExpired()
        {
            var properties = new AuthenticationProperties();
            properties.Items[Auth0Constants.SessionExpiryItemKey] = "garbage";

            SessionExpiryHelpers.IsSessionExpired(properties, long.MaxValue).Should().BeFalse();
        }

        [Fact]
        public void IsSessionExpired_PastCeiling_IsExpired()
        {
            var ceiling = 1_000_000L;
            var properties = new AuthenticationProperties();
            properties.Items[Auth0Constants.SessionExpiryItemKey] = ceiling.ToString(CultureInfo.InvariantCulture);

            SessionExpiryHelpers.IsSessionExpired(properties, ceiling + 1).Should().BeTrue();
        }

        [Fact]
        public void IsSessionExpired_BeforeCeiling_IsNotExpired()
        {
            var ceiling = 1_000_000L;
            var properties = new AuthenticationProperties();
            properties.Items[Auth0Constants.SessionExpiryItemKey] = ceiling.ToString(CultureInfo.InvariantCulture);

            SessionExpiryHelpers.IsSessionExpired(properties, ceiling - 3600).Should().BeFalse();
        }
    }
}
