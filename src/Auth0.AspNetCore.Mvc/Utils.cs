using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace Auth0.AspNetCore.Mvc
{
    internal static class Utils
    {
        public static void AddRange<T>(this ICollection<T> collection, ICollection<T> rangeToAdd)
        {
            foreach (var item in rangeToAdd)
            {
                collection.Add(item);
            }
        }

        public static string CreateAgentString()
        {
            var sdkVersion = typeof(AuthenticationBuilderExtensions).GetTypeInfo().Assembly.GetName().Version;
            var agentJson = $"{{\"name\":\"aspnetcore-mvc\",\"version\":\"{sdkVersion.Major}.{sdkVersion.Minor}.{sdkVersion.Revision}\"}}";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(agentJson));
        }
    }
}
