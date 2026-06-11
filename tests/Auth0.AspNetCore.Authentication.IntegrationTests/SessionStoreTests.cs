using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using Xunit;

namespace Auth0.AspNetCore.Authentication.IntegrationTests
{
    public class SessionStoreTests
    {
        private const string CustomCookieScheme = "Custom.Cookies";

        [Fact]
        public void WithSessionStore_Instance_SetsSessionStoreOnDefaultCookieScheme()
        {
            var store = new FakeTicketStore();
            var provider = BuildProvider(builder => builder.WithSessionStore(store));

            var cookieOptions = GetCookieOptions(provider, CookieAuthenticationDefaults.AuthenticationScheme);

            cookieOptions.SessionStore.Should().BeSameAs(store);
        }

        [Fact]
        public void WithSessionStore_TypeParam_SetsSessionStoreResolvedFromContainer()
        {
            var provider = BuildProvider(builder => builder.WithSessionStore<FakeTicketStore>());

            var cookieOptions = GetCookieOptions(provider, CookieAuthenticationDefaults.AuthenticationScheme);

            cookieOptions.SessionStore.Should().BeOfType<FakeTicketStore>();
        }

        [Fact]
        public void WithSessionStore_TypeParam_ResolvesDependenciesFromContainer()
        {
            // A store with a constructor dependency proves the type-param overload goes
            // through the container rather than new-ing the store itself.
            var provider = BuildProvider(
                builder => builder.WithSessionStore<DependentTicketStore>(),
                services => services.AddSingleton(new StoreDependency("injected")));

            var cookieOptions = GetCookieOptions(provider, CookieAuthenticationDefaults.AuthenticationScheme);

            cookieOptions.SessionStore.Should().BeOfType<DependentTicketStore>();
            ((DependentTicketStore)cookieOptions.SessionStore!).Dependency.Value.Should().Be("injected");
        }

        [Fact]
        public void WithSessionStore_TargetsConfiguredCookieScheme_NotJustTheDefault()
        {
            // The whole point of the wrapper: it attaches to the SDK's resolved cookie scheme,
            // so a custom CookieAuthenticationScheme still gets the store without the caller
            // having to name it.
            var store = new FakeTicketStore();
            var provider = BuildProvider(
                builder => builder.WithSessionStore(store),
                configureAuth0: options => options.CookieAuthenticationScheme = CustomCookieScheme);

            GetCookieOptions(provider, CustomCookieScheme).SessionStore.Should().BeSameAs(store);
        }

        [Fact]
        public void WithSessionStore_WhenNotCalled_LeavesSessionStoreNull()
        {
            var provider = BuildProvider(_ => { });

            GetCookieOptions(provider, CookieAuthenticationDefaults.AuthenticationScheme)
                .SessionStore.Should().BeNull();
        }

        private static ServiceProvider BuildProvider(
            System.Action<Auth0WebAppAuthenticationBuilder> configureBuilder,
            System.Action<IServiceCollection>? configureServices = null,
            System.Action<Auth0WebAppOptions>? configureAuth0 = null)
        {
            var services = new ServiceCollection();
            services.AddLogging();
            configureServices?.Invoke(services);

            var builder = services.AddAuth0WebAppAuthentication(options =>
            {
                options.Domain = "test.auth0.com";
                options.ClientId = "client-id";
                options.ClientSecret = "client-secret";
                configureAuth0?.Invoke(options);
            });

            configureBuilder(builder);

            return services.BuildServiceProvider();
        }

        private static CookieAuthenticationOptions GetCookieOptions(ServiceProvider provider, string scheme)
        {
            return provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
        }

        private class FakeTicketStore : ITicketStore
        {
            public Task<string> StoreAsync(AuthenticationTicket ticket) => Task.FromResult("key");
            public Task RenewAsync(string key, AuthenticationTicket ticket) => Task.CompletedTask;
            public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult<AuthenticationTicket?>(null);
            public Task RemoveAsync(string key) => Task.CompletedTask;
        }

        private class StoreDependency
        {
            public StoreDependency(string value) => Value = value;
            public string Value { get; }
        }

        private class DependentTicketStore : ITicketStore
        {
            public DependentTicketStore(StoreDependency dependency) => Dependency = dependency;
            public StoreDependency Dependency { get; }

            public Task<string> StoreAsync(AuthenticationTicket ticket) => Task.FromResult("key");
            public Task RenewAsync(string key, AuthenticationTicket ticket) => Task.CompletedTask;
            public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult<AuthenticationTicket?>(null);
            public Task RemoveAsync(string key) => Task.CompletedTask;
        }
    }
}
