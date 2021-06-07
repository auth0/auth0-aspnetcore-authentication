using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Mvc.Playground
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuth0Mvc(options =>
            {
                options.Domain = Configuration["Auth0:Domain"];
                options.ClientId = Configuration["Auth0:ClientId"];
                options.ClientSecret = Configuration["Auth0:ClientSecret"];
                options.Audience = Configuration["Auth0:Audience"];
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.UseRefreshTokens = true;
            });

            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.Use(async (context, next) =>
            {
                var idToken = await context.GetTokenAsync("id_token");
                var refreshToken = await context.GetTokenAsync("refresh_token");

                var options = context.RequestServices.GetRequiredService<Auth0Options>();

                if (options.UseRefreshTokens && !string.IsNullOrEmpty(idToken) && string.IsNullOrEmpty(refreshToken))
                {
                    var authenticationProperties = new AuthenticationPropertiesBuilder().WithRedirectUri("/Account/Login").Build();

                    await context.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }

                // Call the next delegate/middleware in the pipeline
                await next();
            });


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
