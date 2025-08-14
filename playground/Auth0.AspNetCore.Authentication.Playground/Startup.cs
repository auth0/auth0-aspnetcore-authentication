using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Auth0.AspNetCore.Authentication.BackchannelLogout;
using Microsoft.Extensions.Caching.Distributed;

namespace Auth0.AspNetCore.Authentication.Playground;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

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
            }).WithBackchannelLogout();



        // The above configuration works but is not suitable for production as it uses an InMemory cache to store the logout token
        // Instead, for production use any of the following, additional, configuration.
        // Note: For the statefull scenario's, ensure to uncomment `ConfigureStatefullSessions` as well.


        // ** STATELESS **

        // 1. Configure the SDK to use a custom LogoutTokenHandler to store the tokens.
        // 
        // ConfigureServicesAuth0CustomStore(services);


        // ** STATEFUL **

        // Ensure to uncomment this when using any of the below configurations
        // ConfigureStatefullSessions(services);


        // 2. Configure the SDK to use Stateful session and a custom LogoutTokenHandler to store the tokens.
        //
        // ConfigureServicesAuth0StatfullCustomStore(services);


        // 3. Configure the SDK to use Stateful session and a custom LogoutTokenHandler to store the tokens that relies on IDistributedCache.
        //
        // ConfigureServicesAuth0StatfullCustomStoreUsingDistributedCache(services);


        // 4. Configure the SDK to use Stateful session and a custom LogoutTokenHandler to not store the tokens but immediatly clear the session.
        //
        // ConfigureServicesAuth0StatfullInstantSessionClear(services);



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

        app.UseBackchannelLogout();
            
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
        });
    }
}
