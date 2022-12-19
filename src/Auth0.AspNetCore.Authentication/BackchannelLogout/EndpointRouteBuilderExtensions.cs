using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication
{
    public static class EndpointRouteBuilderExtensions
    {
        public static void MapBackchannelEndpoint(this IEndpointRouteBuilder endpoints)
        {
            endpoints.MapPost("backchannel-logout", (context) =>
            {
                var handler = context.RequestServices.GetRequiredService<BackchannelLogoutHandler>();
                return handler.HandleRequestAsync(context);
            })
                .AllowAnonymous();
        }
    }
}
