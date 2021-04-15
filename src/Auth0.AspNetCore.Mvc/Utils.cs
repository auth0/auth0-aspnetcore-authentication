using System.Collections.Generic;

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
    }

}
