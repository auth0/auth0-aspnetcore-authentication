using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication
{
    internal static class Utils
    {
        public static void AddRange<T>(this ICollection<T> collection, ICollection<T> rangeToAdd)
        {
            foreach (var item in rangeToAdd)
            {
                collection.AddSafe(item);
            }
        }

        public static void AddSafe<T>(this ICollection<T> collection, T item)
        {
            if (!collection.Contains(item))
            {
                collection.Add(item);
            }
        }

        public static string CreateAgentString()
        {
            var sdkVersion = typeof(AuthenticationBuilderExtensions).GetTypeInfo().Assembly.GetName().Version;
            var agentJson = $"{{\"name\":\"aspnetcore-authentication\",\"version\":\"{sdkVersion?.Major}.{sdkVersion?.Minor}.{sdkVersion?.Revision}\"}}";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(agentJson));
        }

        public static Func<T, Task> ProxyEvent<T>(Func<T, Task> newHandler, Func<T, Task> originalHandler)
        {
            return async (context) =>
            {
                if (newHandler != null)
                {
                    await newHandler(context);
                }
                if (originalHandler != null)
                {
                    await originalHandler(context);
                }
            };
        }
        
        /// <summary>
        /// Normalizes the given issuer or authority string to a valid HTTPS authority URL.
        /// Trims whitespace and trailing slashes. If the input already starts with "http://" or "https://",
        /// it is returned as-is (after trimming). Otherwise, "https://" is prepended.
        /// </summary>
        /// <param name="issuerOrAuthority">The issuer or authority string to normalize.</param>
        /// <returns>A normalized authority URL string.</returns>
        internal static string ToAuthority(string issuerOrAuthority)
        {
            var normalized = issuerOrAuthority.Trim().TrimEnd('/');
    
            if (!normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                normalized = $"https://{normalized}";
            }
    
            return normalized + "/";
        }
    }
}
