using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure
{
    /// <summary>
    ///  AuthenticationHandler used to Mock the Authentication in Integration Tests that an authenticated user to be available
    ///  See: https://docs.microsoft.com/en-us/aspnet/core/test/integration-tests?view=aspnetcore-5.0#mock-authentication
    /// </summary>
    public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var claims = new[] { new Claim(ClaimTypes.Name, "Test user") };
            var identity = new ClaimsIdentity(claims, "Cookies");
            var principal = new ClaimsPrincipal(new GenericIdentity("Alice", "Cookies"));
            var ticket = new AuthenticationTicket(principal, "Cookies");

            var result = AuthenticateResult.Success(ticket);

            return Task.FromResult(result);
        }
    }
}
