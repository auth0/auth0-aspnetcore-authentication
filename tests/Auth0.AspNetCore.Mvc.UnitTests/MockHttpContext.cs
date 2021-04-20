using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Moq;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class MockHttpContext
    {
        private const string correlationId = "1234";
        private const string correlationCookieName = ".AspNetCore.Correlation.";
        private const string correlationMarker = "N";

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
            MockCookies(httpContext);

            httpContext.Request.Scheme = "https";
            httpContext.Request.Headers[HeaderNames.Host] = "local.auth0.com";

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
            requestFeatureMock.Setup(option => option.Path).Returns("/callback");
            requestFeatureMock.Setup(option => option.Method).Returns("GET");
            requestFeatureMock.Setup(option => option.QueryString).Returns("?code=1234&state=CfDJ8BPb7ELbAedCtEncnDGr4SocdS-70ScvDUW6wIJEez_nfvkmvXHmJGIL8rwIXKMoK5a_Y6fFtxPby0moLCmy8DRqlHg13UroeF8dqvTwFjzMSDOdLzUn9hC2CJUKSUv0Qt1MUfceO1SkCkDMaZeZPLYPACUpR63r24jMAIPxWbaggkkfkriZOlJaWIx08xor6YDsrm8fUpC_XHwVA9ExyrPSNWnTGnlso259Hxh1EkLLujf4iIDkz18G5b8x_CxidLoNfG54NVkmixS24EAd0PGyEBGCS_qJM4B1cuTCm0JrU6oZFD6ppyF9udVe4UW1mAo-5Zvh-YZAf4eEbbScONXudoOvI7aqKPK94xpkMOpiNhZ1emW4flKgU_n9gD5gEg");

            context.Features.Set<IHttpRequestFeature>(requestFeatureMock.Object);

        }

        private void MockCookies(HttpContext context)
        {
            var nonceCookieName = ".AspNetCore.OpenIdConnect.Nonce.";
            var nonce = "CfDJ8BPb7ELbAedCtEncnDGr4SpNj8BEWMkijn88ww89NRomWf-Z7ybhUG_3jMoF-bYomogA2D-yKKIdhnVjMvIUb5YhnFBVvk7Q24g522Uz-QeZKDcwtekocl0ND2jV0lQaVV_zfymKgdT0F6s1CgkYhoeETWc8y4RvdTjetRs96hegftRkAOWznefwwH_mkC3-JmFcr0D_2P9M49RqjRXxBFRhRI3rWcLGQSPTCndbBYZDk3tB4Nx4yCPLSgM7U5fSg2pu9lNmvc3XFlyWqPPb0Wo";
            var cookiesFeatureMock = new Mock<IResponseCookiesFeature>();
            var cookiesMock = new MockResponseCookies();

            cookiesFeatureMock.Setup(option => option.Cookies).Returns(cookiesMock);

            var requestCookiesFeatureMock = new Mock<IRequestCookiesFeature>();
            var requestCookiesMock = new MockRequestCookies(new Dictionary<string, string>
            {
                [correlationCookieName + correlationId] = correlationMarker,
                [nonceCookieName + nonce] = correlationMarker
            });


            requestCookiesFeatureMock.Setup(option => option.Cookies).Returns(requestCookiesMock);

            context.Features.Set<IRequestCookiesFeature>(requestCookiesFeatureMock.Object);
        }
    }
}
