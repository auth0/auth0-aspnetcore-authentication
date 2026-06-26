using FluentAssertions;
using System;
using System.Collections.Generic;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class ConnectionTokenSetHelpersTests
    {
        [Fact]
        public void FindConnectionTokenSet_ReturnsNull_WhenSetsNull()
        {
            ConnectionTokenSetHelpers.FindConnectionTokenSet(null, "google-oauth2").Should().BeNull();
        }

        [Fact]
        public void FindConnectionTokenSet_MatchesByConnection()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sets = new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet { Connection = "github", AccessToken = "gh", ExpiresAt = now + 100 },
                new ConnectionTokenSet { Connection = "google-oauth2", AccessToken = "goog", ExpiresAt = now + 100 }
            };

            ConnectionTokenSetHelpers.FindConnectionTokenSet(sets, "google-oauth2")!.AccessToken.Should().Be("goog");
        }

        [Fact]
        public void FindConnectionTokenSet_ReturnsNull_WhenNoMatch()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sets = new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet { Connection = "github", AccessToken = "gh", ExpiresAt = now + 100 }
            };

            ConnectionTokenSetHelpers.FindConnectionTokenSet(sets, "google-oauth2").Should().BeNull();
        }

        [Fact]
        public void Upsert_AppendsNewConnection()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var response = new AccessTokenResponse { AccessToken = "goog", ExpiresIn = 3600, Scope = "email" };

            var result = ConnectionTokenSetHelpers.UpsertConnectionTokenSet(null, "google-oauth2", response);

            result.Should().HaveCount(1);
            result[0].Connection.Should().Be("google-oauth2");
            result[0].AccessToken.Should().Be("goog");
            result[0].Scope.Should().Be("email");
            result[0].ExpiresAt.Should().BeGreaterThan(now);
        }

        [Fact]
        public void Upsert_ReplacesExistingConnectionInPlace()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sets = new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet { Connection = "google-oauth2", AccessToken = "old", ExpiresAt = now + 100, Scope = "email" }
            };
            var response = new AccessTokenResponse { AccessToken = "new", ExpiresIn = 3600, Scope = "email profile" };

            var result = ConnectionTokenSetHelpers.UpsertConnectionTokenSet(sets, "google-oauth2", response);

            result.Should().HaveCount(1);
            result[0].AccessToken.Should().Be("new");
            result[0].Scope.Should().Be("email profile");
        }

        [Fact]
        public void Upsert_PrunesExpiredEntries()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sets = new List<ConnectionTokenSet>
            {
                new ConnectionTokenSet { Connection = "github", AccessToken = "stale", ExpiresAt = now - 10 }
            };
            var response = new AccessTokenResponse { AccessToken = "goog", ExpiresIn = 3600, Scope = "" };

            var result = ConnectionTokenSetHelpers.UpsertConnectionTokenSet(sets, "google-oauth2", response);

            result.Should().HaveCount(1);
            result[0].Connection.Should().Be("google-oauth2");
        }
    }
}
