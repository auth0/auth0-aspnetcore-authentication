using System.Collections.Generic;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class MockResponseCookies : IResponseCookies
    {
        private static IDictionary<string, string> _storage = new Dictionary<string, string>();
        public void Append(string key, string value)
        {
            _storage[key] = value;
        }

        public void Append(string key, string value, CookieOptions options)
        {
            _storage[key] = value;
        }

        public void Delete(string key)
        {
            _storage.Remove(key);
        }

        public void Delete(string key, CookieOptions options)
        {
            _storage.Remove(key);
        }
    }
}
