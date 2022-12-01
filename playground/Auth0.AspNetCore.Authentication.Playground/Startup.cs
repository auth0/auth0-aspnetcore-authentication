using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Auth0.AspNetCore.Authentication;

namespace Auth0.AspNetCore.Authentication.Playground
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
            services
                .AddAuth0WebAppAuthentication(PlaygroundConstants.AuthenticationScheme, options =>
                {
                    options.Domain = Configuration["Auth0:Domain"];
                    options.ClientId = Configuration["Auth0:ClientId"];
                    options.ClientSecret = Configuration["Auth0:ClientSecret"];
                })
                .WithAccessToken(options =>
                {
                    options.Audience = Configuration["Auth0:Audience"];
                    options.UseRefreshTokens = true;

                    options.Events = new Auth0WebAppWithAccessTokenEvents
                    {
                        OnMissingRefreshToken = async (context) =>
                        {
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                            await context.ChallengeAsync(PlaygroundConstants.AuthenticationScheme, authenticationProperties);
                        }
                    };
                });
            services.AddSingleton<ITicketStore, Auth0TicketStore2>();
            services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
                .Configure<ITicketStore>((options, store) =>
                {
                    options.SessionStore = store;
                });


            services
                .AddAuth0WebAppAuthentication(PlaygroundConstants.AuthenticationScheme2, options =>
                {
                    options.Domain = Configuration["Auth02:Domain"];
                    options.ClientId = Configuration["Auth02:ClientId"];
                    options.ClientSecret = Configuration["Auth02:ClientSecret"];
                    options.SkipCookieMiddleware = true;
                    options.CallbackPath = "/callback2";
                }).WithAccessToken(options =>
                {
                    options.Audience = Configuration["Auth02:Audience"];
                    options.UseRefreshTokens = true;

                    options.Events = new Auth0WebAppWithAccessTokenEvents
                    {
                        OnMissingRefreshToken = async (context) =>
                        {
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            var authenticationProperties = new LoginAuthenticationPropertiesBuilder().WithRedirectUri("/").Build();
                            await context.ChallengeAsync(PlaygroundConstants.AuthenticationScheme2, authenticationProperties);
                        }
                    };
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

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapBackchannelEndpoint();
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
