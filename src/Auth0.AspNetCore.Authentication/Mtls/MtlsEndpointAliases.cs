using System.Text.Json;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Auth0.AspNetCore.Authentication.Mtls
{
    /// <summary>
    /// Reads a single endpoint out of the <c>mtls_endpoint_aliases</c> object in an
    /// <see cref="OpenIdConnectConfiguration"/>. Microsoft's configuration model does not deserialize
    /// <c>mtls_endpoint_aliases</c> into a typed property, so it arrives in
    /// <see cref="OpenIdConnectConfiguration.AdditionalData"/> as a nested
    /// <see cref="JsonElement"/> object that must be unwrapped rather than cast.
    /// </summary>
    internal static class MtlsEndpointAliases
    {
        internal const string AliasesKey = "mtls_endpoint_aliases";

        /// <summary>
        /// Returns the aliased URL for <paramref name="endpointName"/> (for example
        /// <c>token_endpoint</c>), or <c>null</c> when <c>mtls_endpoint_aliases</c> is absent,
        /// is not a JSON object, or does not contain a string value for that endpoint.
        /// </summary>
        public static string? TryGetAlias(OpenIdConnectConfiguration? configuration, string endpointName)
        {
            if (configuration?.AdditionalData == null)
            {
                return null;
            }

            if (!configuration.AdditionalData.TryGetValue(AliasesKey, out var raw))
            {
                return null;
            }

            if (raw is JsonElement aliases &&
                aliases.ValueKind == JsonValueKind.Object &&
                aliases.TryGetProperty(endpointName, out var endpoint) &&
                endpoint.ValueKind == JsonValueKind.String)
            {
                return endpoint.GetString();
            }

            return null;
        }
    }
}
