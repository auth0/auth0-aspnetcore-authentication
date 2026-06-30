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

        [Theory]
        [InlineData("Bearer abc")]
        [InlineData("bearer abc")]
        [InlineData("BEARER abc")]
        public void Rejects_SubjectToken_With_Bearer_Prefix(string token)
        {
            var req = Valid();
            req.SubjectToken = token;
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*Bearer*");
        }

        [Theory]
        [InlineData(" external-token-value")]
        [InlineData("external-token-value ")]
        [InlineData(" external-token-value ")]
        public void Rejects_SubjectToken_With_Surrounding_Whitespace(string token)
        {
            var req = Valid();
            req.SubjectToken = token;
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().Throw<CustomTokenExchangeException>().WithMessage("*whitespace*");
        }

        [Fact]
        public void Accepts_Short_Valid_Urn_SubjectTokenType()
        {
            var req = Valid();
            req.SubjectTokenType = "urn:a:b"; // 7 chars — a legal URN, no length floor
            var act = () => CustomTokenExchangeRequestValidator.Validate(req);
            act.Should().NotThrow();
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
