using System.Linq;
using Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure;
using Auth0.AspNetCore.Authentication.Mtls;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Mtls
{
    public class MtlsCnfInspectorTests
    {
        private const string Header = "eyJhbGciOiJSUzI1NiJ9";
        private const string PayloadWithCnf = "eyJjbmYiOnsieDV0I1MyNTYiOiJhYmMifX0";
        private const string PayloadNoCnf = "eyJzdWIiOiJ1MSJ9";

        private const string ExpectedWarning =
            "mTLS is enabled but the access token has no `cnf.x5t#S256` claim; the token is not sender-constrained. " +
            "Configure Token Sender-Constraining on the API.";

        private static (MtlsCnfInspector Inspector, CapturingLoggerProvider Sink) Build()
        {
            var sink = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(sink));
            return (new MtlsCnfInspector(factory), sink);
        }

        [Fact]
        public void Warns_When_Jwt_Has_No_Cnf()
        {
            var (inspector, sink) = Build();

            inspector.Inspect("client-1", $"{Header}.{PayloadNoCnf}.sig");

            sink.Logs.Should().ContainSingle(l => l.Level == LogLevel.Warning && l.Message == ExpectedWarning);
        }

        [Fact]
        public void Silent_When_Cnf_Present()
        {
            var (inspector, sink) = Build();

            inspector.Inspect("client-1", $"{Header}.{PayloadWithCnf}.sig");

            sink.Logs.Should().BeEmpty();
        }

        [Fact]
        public void Silent_For_Opaque_Token()
        {
            var (inspector, sink) = Build();

            inspector.Inspect("client-1", "opaque");

            sink.Logs.Should().BeEmpty();
        }

        [Fact]
        public void Warns_Only_Once_Per_ClientId()
        {
            var (inspector, sink) = Build();

            inspector.Inspect("client-1", $"{Header}.{PayloadNoCnf}.sig");
            inspector.Inspect("client-1", $"{Header}.{PayloadNoCnf}.sig");
            inspector.Inspect("client-1", $"{Header}.{PayloadNoCnf}.sig");

            sink.Logs.Count(l => l.Level == LogLevel.Warning).Should().Be(1);
        }
    }
}
