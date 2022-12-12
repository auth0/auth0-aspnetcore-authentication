using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;

namespace Auth0.AspNetCore.Authentication
{
    public class Auth0DistributedCache : IDistributedCache
    {
        private Dictionary<string, byte[]> _store = new Dictionary<string, byte[]>();


        public byte[]? Get(string key)
        {
            return this._store.GetValueOrDefault(key);
        }

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            return Task.FromResult(this._store.GetValueOrDefault(key));
        }

        public void Refresh(string key)
        {
            throw new NotImplementedException();
        }

        public Task RefreshAsync(string key, CancellationToken token = default)
        {
            throw new NotImplementedException();
        }

        public void Remove(string key)
        {
            this._store.Remove(key);
        }

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            this._store.Remove(key);
            return Task.CompletedTask;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            this._store.Add(key, value);
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            this._store.Add(key, value);
            return Task.CompletedTask;
        }
    }
}
