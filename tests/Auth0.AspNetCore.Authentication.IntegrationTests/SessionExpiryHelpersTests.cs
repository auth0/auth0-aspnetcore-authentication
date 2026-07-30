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

        [Theory]
        // A millisecond value (seconds * 1000) is far above the cap and must be rejected as "no
        // ceiling" so a units mistake in an Action can't silently switch off enforcement.
        [InlineData("1712345678000")]
        [InlineData("10000000000")]
        public void TryParseCeiling_RejectsValuesAtOrAboveCap(string raw)
        {
            SessionExpiryHelpers.TryParseCeiling(raw, out var seconds).Should().BeFalse();
            seconds.Should().Be(0);
        }

        [Fact]
        public void TryParseCeiling_AcceptsValueJustBelowCap()
        {
            SessionExpiryHelpers.TryParseCeiling("9999999999", out var seconds).Should().BeTrue();
            seconds.Should().Be(9999999999L);
        }

        [Theory]
        // Zero and negative are numbers, so they clear the range check — but they are not a real
        // forward-in-time ceiling. They must fall through to "no ceiling" (fail open) rather than
        // reaching the at-or-before-iat throw and locking the user out.
        [InlineData("0")]
        [InlineData("-1")]
        [InlineData("-1712345678")]
        public void TryParseCeiling_ReturnsFalse_ForZeroOrNegative(string raw)
        {
            SessionExpiryHelpers.TryParseCeiling(raw, out var seconds).Should().BeFalse();
            seconds.Should().Be(0);
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
