using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class MockHttpContext
    {
        private readonly ServiceCollection _serviceCollection;
        private readonly Action<ServiceCollection> _configureServiceCollection;

        private MockHttpContext(ServiceCollection serviceCollection, Action<ServiceCollection> configure)
        {
            _serviceCollection = serviceCollection;
            _configureServiceCollection = configure;
        }

        public static MockHttpContext Configure(Action<ServiceCollection> cb)
        {
            return new MockHttpContext(new ServiceCollection(), cb);
        }

        public async Task RunAsync(Func<HttpContext, Task> cb)
        {
            var httpContext = new DefaultHttpContext();

            httpContext.Request.Scheme = "https";
            httpContext.Request.Headers[HeaderNames.Host] = "local.auth0.com";

            _configureServiceCollection(_serviceCollection);

            httpContext.RequestServices = _serviceCollection.AddLogging(logging => logging.AddConsole()).BuildServiceProvider();

            await cb(httpContext);
        }
    }
}
