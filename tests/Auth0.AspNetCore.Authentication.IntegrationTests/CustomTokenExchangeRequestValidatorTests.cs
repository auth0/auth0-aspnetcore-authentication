using System;
using FluentAssertions;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class CustomTokenExchangeRequestValidatorTests
    {
        private static CustomTokenExchangeRequest Valid() => new CustomTokenExchangeRequest
        {
            SubjectToken = "external-token-value",
            SubjectTokenType = "urn:acme:legacy-token"
        };

        [Fact]
        public void Accepts_A_Valid_Minimal_Request()
        {
            var act = () => CustomTokenExchangeRequestValidator.Validate(Valid());
            act.Should().NotThrow();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Rejects_Empty_SubjectToken(string? token)
        {
            var req = Valid();
            req.SubjectToken = token!;
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*subject_token*");
        }

        [Fact]
        public void Rejects_SubjectToken_With_Bearer_Prefix()
        {
            var req = Valid();
            req.SubjectToken = "Bearer abc";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*Bearer*");
        }

        [Fact]
        public void Rejects_SubjectTokenType_Shorter_Than_10_Chars()
        {
            var req = Valid();
            req.SubjectTokenType = "urn:a:b"; // 7 chars
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*subject_token_type*");
        }

        [Fact]
        public void Rejects_SubjectTokenType_Longer_Than_100_Chars()
        {
            var req = Valid();
            req.SubjectTokenType = "urn:acme:" + new string('a', 100);
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*subject_token_type*");
        }

        [Fact]
        public void Rejects_SubjectTokenType_That_Is_Not_A_Uri()
        {
            var req = Valid();
            req.SubjectTokenType = "not a uri!!";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*subject_token_type*");
        }

        [Theory]
        [InlineData("urn:ietf:params:oauth:token-type:id_token")]
        [InlineData("urn:auth0:something:reserved")]
        public void Rejects_Reserved_Namespaces(string reserved)
        {
            var req = Valid();
            req.SubjectTokenType = reserved;
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*reserved*");
        }

        [Theory]
        [InlineData("urn:acme:legacy-token")]
        [InlineData("https://mycompany.com/token-type/v1")]
        public void Accepts_Valid_Custom_Uri_SubjectTokenTypes(string type)
        {
            var req = Valid();
            req.SubjectTokenType = type;
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().NotThrow();
        }

        [Fact]
        public void Rejects_ActorToken_Without_ActorTokenType()
        {
            var req = Valid();
            req.ActorToken = "actor-token";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*actor_token_type*");
        }

        [Fact]
        public void Rejects_ActorTokenType_Without_ActorToken()
        {
            var req = Valid();
            req.ActorTokenType = "urn:acme:actor";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*actor_token*");
        }

        [Fact]
        public void Rejects_ActorTokenType_That_Is_Not_A_Uri()
        {
            var req = Valid();
            req.ActorToken = "actor-token";
            req.ActorTokenType = "not a uri!!";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*actor_token_type*");
        }

        [Fact]
        public void Accepts_Valid_Actor_Pair()
        {
            var req = Valid();
            req.ActorToken = "actor-token";
            req.ActorTokenType = "urn:acme:actor-token";
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().NotThrow();
        }
    }
}
