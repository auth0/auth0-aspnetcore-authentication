using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout;

internal static class LogoutTokenValidator
{
    internal class EventsClaimPayload
    {
        [JsonPropertyName("http://schemas.openid.net/event/backchannel-logout")]
        public object? BackChannelLogoutProperty { get; set; }
    }
        
    public static void Validate(JwtSecurityToken token)
    {
        var sid = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sid)?.Value;

        if (sid == null)
        {
            throw new LogoutTokenValidationException("Session Id (sid) claim must be a string present in the logout token.");
        }

        var iat = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Iat)?.Value;

        if (iat == null)
        {
            throw new LogoutTokenValidationException("Issued At (iat) claim must be an integer present in the logout token.");
        }
            
        var nonce = token.Claims.SingleOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Nonce)?.Value;

        if (nonce != null)
        {
            throw new LogoutTokenValidationException("Nonce (nonce) claim must not be present in the logout token.");
        }
            
        var events = token.Claims.SingleOrDefault(claim => claim.Type == "events")?.Value;

        if (events == null)
        {
            throw new LogoutTokenValidationException("Events (events) claim must be present in the logout token.");
        }
        else
        {
            var parsedEvents = JsonSerializer.Deserialize<EventsClaimPayload>(events);

            if (parsedEvents is null)
            {
                throw new LogoutTokenValidationException("Events (events) claim must contain a name in the logout token.");
            }
            if (parsedEvents.BackChannelLogoutProperty is null)
            {
                throw new LogoutTokenValidationException("Events (events) claim must contain a 'http://schemas.openid.net/event/backchannel-logout' property in the logout token.");
            }
        }
    }
}