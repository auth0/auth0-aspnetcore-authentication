using Microsoft.Extensions.Configuration;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public class TestConfiguration
    {
        private static IConfiguration _configuration;

        public static IConfiguration GetConfiguration()
        {
            if (_configuration == null)
            {
                _configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            }

            return _configuration;
        }
    }
}
