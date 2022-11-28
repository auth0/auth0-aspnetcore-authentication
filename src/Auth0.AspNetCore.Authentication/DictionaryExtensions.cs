using System;
using System.Collections.Generic;

namespace Auth0.AspNetCore.Authentication;

public static class DictionaryExtensions
{
    public static bool GetBooleanOrDefault<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, bool defaultValue)
    {
        if (dictionary.TryGetValue(key, out var value))
        {
            return Convert.ToBoolean(value);
        };

        return defaultValue;
    }
}