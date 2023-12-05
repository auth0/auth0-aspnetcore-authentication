using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0.AspNetCore.Authentication.BackchannelLogout
{
    public static class ApplicationBuilderExtensions
    {
        public static void UseBackchannelLogout(this IApplicationBuilder app, string path = "/backchannel-logout")
        {
            app.Map(path, HandleBackchannelLogout);
        }
        
        private static void HandleBackchannelLogout(IApplicationBuilder app)
        {
            app.Run(async context =>
            {
                if (context.Request.Method == "POST")
                {
                    var handler = context.RequestServices.GetRequiredService<BackchannelLogoutHandler>();
                    await handler.HandleRequestAsync(context);
                }
                else
                {
                    await context.WriteStatusCodeAsync(405);
                }
            });
        }
    }
}
