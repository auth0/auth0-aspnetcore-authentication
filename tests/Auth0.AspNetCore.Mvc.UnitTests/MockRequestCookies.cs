using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Auth0.AspNetCore.Mvc.UnitTests
{
    public class MockRequestCookies : IRequestCookieCollection
    {
        private static IDictionary<string, string> _storage = new Dictionary<string, string>();

        public string this[string key]
        {
            get
            {
                if (key.StartsWith(".AspNetCore.Correlation"))
                {
                    var mockKey = _storage.Keys.SingleOrDefault(key => key.StartsWith(".AspNetCore.Correlation"));
                    return _storage[mockKey ?? key];
                }
                return _storage.Keys.Any(k => k == key) ? _storage[key] : null;
            }
        }


        public MockRequestCookies(IDictionary<string, string> storage)
        {
            _storage = storage;
        }
        public int Count => _storage.Count;

        public ICollection<string> Keys => _storage.Keys;

        public bool ContainsKey(string key)
        {
            return _storage.ContainsKey(key);
        }

        public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
        {
            return _storage.GetEnumerator();
        }

        public bool TryGetValue(string key, [MaybeNullWhen(false)] out string value)
        {
            return _storage.TryGetValue(key, out value);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
