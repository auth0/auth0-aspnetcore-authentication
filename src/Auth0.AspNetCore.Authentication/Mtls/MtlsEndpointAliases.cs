using System;
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

        /// <summary>
        /// Returns the aliased URL for <paramref name="endpointName"/>, or throws
        /// <see cref="InvalidOperationException"/> with an actionable message when the alias is absent.
        /// This is the fail-closed counterpart to <see cref="TryGetAlias"/>: callers that cannot safely
        /// fall back to the standard (non-mTLS) endpoint use this so the same misconfiguration surfaces
        /// the same clear error everywhere, rather than a downstream <c>invalid_client</c>.
        /// </summary>
        public static string GetRequiredAlias(OpenIdConnectConfiguration? configuration, string endpointName)
        {
            var alias = TryGetAlias(configuration, endpointName);
            if (string.IsNullOrEmpty(alias))
            {
                throw new InvalidOperationException(
                    $"mTLS is enabled but the authorization server discovery document does not advertise " +
                    $"`mtls_endpoint_aliases.{endpointName}`. Ensure mTLS endpoint aliases are enabled on your Auth0 tenant.");
            }

            return alias!;
        }
    }
}
