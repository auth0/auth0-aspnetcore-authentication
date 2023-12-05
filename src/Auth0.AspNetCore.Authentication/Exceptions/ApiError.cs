using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Auth0.AspNetCore.Authentication.Exceptions;

/// <summary>
/// Error information captured from a failed API request.
/// </summary>
public class ApiError
{
    /// <summary>
    /// Description of the failing HTTP Status Code.
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    /// <summary>
    /// Description of the error.
    /// </summary>
    [JsonPropertyName("error_description")]
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Parse a <see cref="HttpResponseMessage"/> into an <see cref="ApiError"/> asynchronously.
    /// </summary>
    /// <param name="response"><see cref="HttpResponseMessage"/> to parse.</param>
    /// <returns><see cref="Task"/> representing the operation and associated <see cref="ApiError"/> on
    /// successful completion.</returns>
    public static async Task<ApiError?> Parse(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return Parse(content);
    }

    internal static ApiError Parse(string content)
    {
        try
        {
            return JsonSerializer.Deserialize<ApiError>(content) ?? new ApiError
            {
                Error = content,
                Message = content
            };
        }
        catch (JsonException)
        {
            return new ApiError
            {
                Error = content,
                Message = content
            };
        }
    }
    
}