using FluentAssertions;
using System;
using System.Collections.Generic;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class TokenSetHelpersTests
    {
        [Theory]
        [InlineData(null, new string[0])]
        [InlineData("", new string[0])]
        [InlineData("   ", new string[0])]
        [InlineData("a", new[] { "a" })]
        [InlineData("a b c", new[] { "a", "b", "c" })]
        [InlineData("  a   b  ", new[] { "a", "b" })]
        public void ParseScopes_SplitsAndFilters(string? input, string[] expected)
        {
            TokenSetHelpers.ParseScopes(input).Should().Equal(expected);
        }

        [Fact]
        public void MergeScopes_IsOrderPreservingUnion_NotSorted()
        {
            // default scopes first, request scopes appended, dedup, original order kept
            TokenSetHelpers.MergeScopes("c b", "b a").Should().Be("c b a");
        }

        [Fact]
        public void MergeScopes_HandlesNulls()
        {
            TokenSetHelpers.MergeScopes(null, "a b").Should().Be("a b");
            TokenSetHelpers.MergeScopes("a b", null).Should().Be("a b");
            TokenSetHelpers.MergeScopes(null, null).Should().Be("");
        }

        [Fact]
        public void CompareScopes_NonStrict_IsSupersetMembership()
        {
            TokenSetHelpers.CompareScopes("a b c", "a b").Should().BeTrue();
            TokenSetHelpers.CompareScopes("a b", "a b c").Should().BeFalse();
        }

        [Fact]
        public void CompareScopes_Strict_RequiresEqualSets()
        {
            TokenSetHelpers.CompareScopes("a b", "b a", strict: true).Should().BeTrue();
            TokenSetHelpers.CompareScopes("a b c", "a b", strict: true).Should().BeFalse();
        }

        [Fact]
        public void GetScopeForAudience_PrefersPerAudienceMap()
        {
            var map = new Dictionary<string, string> { ["api://orders"] = "read:orders" };
            TokenSetHelpers.GetScopeForAudience("default", map, "api://orders").Should().Be("read:orders");
            TokenSetHelpers.GetScopeForAudience("default", map, "api://other").Should().Be("default");
            TokenSetHelpers.GetScopeForAudience("default", null, "api://orders").Should().Be("default");
        }

        [Fact]
        public void MergeScopeWithDefaults_UnionsDefaultsWithRequest()
        {
            var map = new Dictionary<string, string> { ["api://orders"] = "read:orders" };
            TokenSetHelpers.MergeScopeWithDefaults("write:orders", "api://orders", "openid", map)
                .Should().Be("read:orders write:orders");
        }

        [Fact]
        public void MergeScopeWithDefaults_ReturnsNullWhenEmpty()
        {
            TokenSetHelpers.MergeScopeWithDefaults(null, "api://x", null, null).Should().BeNull();
        }

        [Fact]
        public void FindAccessTokenSet_PrefersExactThenSmallestSuperset()
        {
            var sets = new List<AccessTokenSet>
            {
                new AccessTokenSet { Audience = "api", AccessToken = "big", Scope = "a b c", RequestedScope = "a b c" },
                new AccessTokenSet { Audience = "api", AccessToken = "small", Scope = "a b", RequestedScope = "a b" },
            };

            // smallest superset for "a"
            TokenSetHelpers.FindAccessTokenSet(sets, "api", "a", ScopeMatchMode.RequestedScope)!.AccessToken.Should().Be("small");
            // exact match
            TokenSetHelpers.FindAccessTokenSet(sets, "api", "a b c", ScopeMatchMode.RequestedScope)!.AccessToken.Should().Be("big");
            // no match for different audience
            TokenSetHelpers.FindAccessTokenSet(sets, "other", "a", ScopeMatchMode.RequestedScope).Should().BeNull();
        }

        [Fact]
        public void UpsertAccessTokenSet_AppendsNewEntry()
        {
            var response = new AccessTokenResponse { AccessToken = "tok", ExpiresIn = 3600, Scope = "read:x" };
            var result = TokenSetHelpers.UpsertAccessTokenSet(null, "api", "read:x", response);

            result.Should().HaveCount(1);
            result[0].AccessToken.Should().Be("tok");
            result[0].Audience.Should().Be("api");
            result[0].Scope.Should().Be("read:x");
            result[0].RequestedScope.Should().Be("read:x");
            result[0].ExpiresAt.Should().BeGreaterThan(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }

        [Fact]
        public void UpsertAccessTokenSet_ReplacesExistingByRequestedScope()
        {
            var existing = new List<AccessTokenSet>
            {
                new AccessTokenSet { Audience = "api", AccessToken = "old", Scope = "a", RequestedScope = "a" }
            };
            var response = new AccessTokenResponse { AccessToken = "new", ExpiresIn = 3600, Scope = "a" };

            var result = TokenSetHelpers.UpsertAccessTokenSet(existing, "api", "a", response);

            result.Should().HaveCount(1);
            result[0].AccessToken.Should().Be("new");
        }

        [Fact]
        public void UpsertAccessTokenSet_MergesRequestedScopeWhenGrantedScopeMatches()
        {
            // cached entry: granted "a", requested "a b". New request "a c" -> granted "a".
            // Should merge requestedScope to "a b c" on the same entry rather than append.
            var existing = new List<AccessTokenSet>
            {
                new AccessTokenSet { Audience = "api", AccessToken = "old", Scope = "a", RequestedScope = "a b" }
            };
            var response = new AccessTokenResponse { AccessToken = "new", ExpiresIn = 3600, Scope = "a" };

            var result = TokenSetHelpers.UpsertAccessTokenSet(existing, "api", "a c", response);

            result.Should().HaveCount(1);
            result[0].RequestedScope.Should().Be("a b c");
            result[0].Scope.Should().Be("a");
            result[0].AccessToken.Should().Be("new");
        }
    }
}
