namespace Auth0.AspNetCore.Mvc
{
    public static class Auth0AuthenticationParmeters
    {
        internal static readonly string Prefix = "Auth0";

        /// <summary>
        /// The key used for the scope entry in AuthenticationProperties.Items
        /// </summary>
        public static string Scope = $"{Prefix}:scope";

        /// <summary>
        /// Generate a key for any extra parameter entry in AuthenticationProperties.Items
        /// </summary>
        /// <returns>The key used for the extra parameter entry in AuthenticationProperties.Items</returns>
        public static string ExtraParameter(string key)
        {
            return $"{Prefix}:{key}";
        }
    }
}
