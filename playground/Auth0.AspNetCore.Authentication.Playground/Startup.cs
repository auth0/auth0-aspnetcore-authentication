using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Session;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Auth0.AspNetCore.Authentication.Playground
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        /// <summary>
        /// Configure the SDK to use a all default settings.
        /// This means the logout token is stored in memory.
        /// 
        /// NOT SUITABLE FOR PRODUCTION
        /// </summary>
        /// <param name="services"></param>
        public void ConfigureServices(IServiceCollection services)
        {

            //ConfigureServicesAuth0(services);
            //ConfigureServicesAuth0CustomStore(services);
            //ConfigureServicesAuth0Statfull(services);
            //ConfigureServicesAuth0StatfullCustomStore(services);
            ConfigureServicesAuth0StatfullInstantSessionClear(services);

            services.AddControllersWithViews();
        }

        private void ConfigureServicesAuth0(IServiceCollection services)
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

        }

        /// <summary>
        /// Configure the SDK to use a custom LogoutTokenHandler to store the tokens.
        /// This means the logout token is stored in memory.
        /// </summary>
        /// <param name="services"></param>
        private void ConfigureServicesAuth0CustomStore(IServiceCollection services)
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

            // Configure a custom LogoutTokenHandler, allowing you to store the logout token wherever you want
            // The Identity information is still stored stateless, in the cookie.
            services.AddTransient<ILogoutTokenHandler, CustomLogoutTokenHandler>();
        }

        /// <summary>
        /// Configure the SDK to use Stateful session without specifying a custom LogoutTokenHandler
        /// This means the logout token is stored in memory.
        ///
        /// NOT SUITABLE FOR PRODUCTION
        /// </summary>
        /// <param name="services"></param>
        private void ConfigureServicesAuth0Statfull(IServiceCollection services)
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

            // Configure a custom ITicketStore to store the Identity Information on the server
            services.AddTransient<ITicketStore, CustomInMemoryTicketStore>();
            // Configure the Cookie Middleware to use the CustomInMemoryTicketStore
            services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>,
              ConfigureCookieAuthenticationOptions>();
        }

        /// <summary>
        /// Configure the SDK to use Stateful session and a custom LogoutTokenHandler to store the tokens.
        /// </summary>
        /// <param name="services"></param>
        private void ConfigureServicesAuth0StatfullCustomStore(IServiceCollection services)
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


            // Configure a custom LogoutTokenHandler, allowing you to store the logout token wherever you want
            services.AddTransient<ILogoutTokenHandler, CustomLogoutTokenHandler>();
            // Configure a custom ITicketStore to store the Identity Information on the server
            services.AddTransient<ITicketStore, CustomInMemoryTicketStore>();
            // Configure the Cookie Middleware to use the CustomInMemoryTicketStore
            services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>,
              ConfigureCookieAuthenticationOptions>();
        }

        /// <summary>
        /// Configure the SDK to use Stateful session and a custom LogoutTokenHandler to not store the tokens but inmediatly clear the session.
        /// </summary>
        /// <param name="services"></param>
        private void ConfigureServicesAuth0StatfullInstantSessionClear(IServiceCollection services)
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

            // Configure a custom LogoutTokenHandler, allowing you to clear the stateful session
            services.AddTransient<ILogoutTokenHandler, CustomClearSessionLogoutTokenHandler>();
            // Configure a custom ITicketStore to store the Identity Information on the server
            services.AddTransient<ITicketStore, CustomInMemoryTicketStore>();
            // Configure the Cookie Middleware to use the CustomInMemoryTicketStore
            services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>,
              ConfigureCookieAuthenticationOptions>();
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

    public class ConfigureCookieAuthenticationOptions
  : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        private readonly ITicketStore _ticketStore;

        public ConfigureCookieAuthenticationOptions(ITicketStore ticketStore)
        {
            _ticketStore = ticketStore;
        }

        public void PostConfigure(string name,
                 CookieAuthenticationOptions options)
        {
            options.SessionStore = _ticketStore;
        }
    }
}
