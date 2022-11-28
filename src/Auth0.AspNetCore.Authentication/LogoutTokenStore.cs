using System;
using System.Collections.Generic;

namespace Auth0.AspNetCore.Authentication
{
    public class LogoutTokenStore
    {
        public static LogoutTokenStore Instance = new LogoutTokenStore();

        private Dictionary<string, string> _store = new Dictionary<string, string>();

        private LogoutTokenStore()
        {
        }


        public void Set(string key, string value)
        {
            this._store.Add(key, value);
        }

        public void Remove(string key)
        {
            this._store.Remove(key);
        }

        public string? Get(string key)
        {
            return this._store.GetValueOrDefault(key);
        }
    }
}

