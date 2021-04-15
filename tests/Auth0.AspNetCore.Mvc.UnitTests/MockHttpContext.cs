using Moq;
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
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
            
            MockRequest(httpContext);
            MockResponse(httpContext);
            MockCookies(httpContext);

            _configureServiceCollection(_serviceCollection);

            httpContext.RequestServices = _serviceCollection.AddLogging(logging => logging.AddConsole()).BuildServiceProvider();

            await cb(httpContext);
        }

        private void MockRequest(HttpContext context)
        {
            var headers = new HeaderDictionary(new Dictionary<string, StringValues> { { HeaderNames.Host, "localhost" } });
            var requestFeatureMock = new Mock<IHttpRequestFeature>();

            requestFeatureMock.Setup(option => option.Scheme).Returns("https");
            requestFeatureMock.Setup(option => option.Headers).Returns(headers);

            context.Features.Set<IHttpRequestFeature>(requestFeatureMock.Object);
        }

        private void MockResponse(HttpContext context)
        {
            var headers = new HeaderDictionary();
            var responseFeatureMock = new Mock<IHttpResponseFeature>();

            responseFeatureMock.Setup(option => option.HasStarted).Returns(true);
            responseFeatureMock.SetupProperty(option => option.StatusCode);
            responseFeatureMock.Setup(option => option.Headers).Returns(headers);

            context.Features.Set<IHttpResponseFeature>(responseFeatureMock.Object);
        }

        private void MockCookies(HttpContext context)
        {
            var cookiesFeatureMock = new Mock<IResponseCookiesFeature>();
            var cookiesMock = new Mock<IResponseCookies>();

            cookiesFeatureMock.Setup(option => option.Cookies).Returns(cookiesMock.Object);

            context.Features.Set<IResponseCookiesFeature>(cookiesFeatureMock.Object);
        }
    }
}
