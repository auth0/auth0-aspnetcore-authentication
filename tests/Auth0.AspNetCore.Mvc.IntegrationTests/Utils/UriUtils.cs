using System;
using System.Collections.Generic;
using System.Linq;

namespace Auth0.AspNetCore.Mvc.IntegrationTests
{
    public class UriUtils
    {
        public static IDictionary<string, string> GetQueryParams(Uri uri)
        {
            return uri.Query.TrimStart('?')
                        .Split(new[] { '&', ';' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(parameter => parameter.Split(new[] { '=' }, StringSplitOptions.RemoveEmptyEntries))
                        .GroupBy(parts => parts[0],
                                 parts => parts.Length > 2 ? string.Join("=", parts, 1, parts.Length - 1) : (parts.Length > 1 ? parts[1] : ""))
                        .ToDictionary(grouping => grouping.Key,
                                      grouping => Uri.UnescapeDataString(string.Join(",", grouping)));
        }
    }
}
