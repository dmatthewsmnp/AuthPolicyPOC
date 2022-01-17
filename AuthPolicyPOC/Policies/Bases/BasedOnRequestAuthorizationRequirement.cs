#nullable disable
using System.Text.Json;
using AuthPolicyPOC.Exceptions;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Policies.Bases;

/// <summary>
///     Provides useful utility methods for repeat functionality for authorization requirements
///     Implements the <see cref="Microsoft.AspNetCore.Authorization.IAuthorizationRequirement" />
/// </summary>
/// <seealso cref="Microsoft.AspNetCore.Authorization.IAuthorizationRequirement" />
public abstract class BasedOnRequestAuthorizationRequirement : IAuthorizationRequirement
{
	protected string[] PathSegments = Array.Empty<string>();
	protected HttpRequest Request = null;

	/// <summary>
	///     Gets the deserialized body from the stream content.
	/// </summary>
	/// <typeparam name="TOutputModel">The type of the templated output model.</typeparam>
	/// <param name="request">The HTTP Request to read the body content from.</param>
	/// <returns>TOutputModel.</returns>
	protected static async ValueTask<TOutputModel> GetDeserializedBody<TOutputModel>(HttpRequest request)
	{
		request.EnableBuffering();

		using var reader = new StreamReader(request.Body, leaveOpen: true);
		var bodyContent = await reader.ReadToEndAsync();

		request.Body.Position = 0;
		reader.DiscardBufferedData();

		return JsonSerializer.Deserialize<TOutputModel>(bodyContent);
	}

	/// <summary>
	/// Parses the request path and populates the path segments
	/// </summary>
	/// <param name="context">The HTTP context to read the request data from.</param>
	/// <param name="expectedPaths">The expected paths to verify, throws an exception if this is wrong.</param>
	/// <exception cref="RequestParsingException">Path is null, cannot process authorization check</exception>
	/// <exception cref="RequestParsingException">Unable to parse request, the wrong path was supplied {0}</exception>
	protected void ParseRequestPath(HttpContext context, IEnumerable<string> expectedPaths)
	{
		Request = context.Request;
		var path = Request.Path.Value;

		if (string.IsNullOrEmpty(path))
		{
			throw new RequestParsingException("Path is null, cannot process authorization check");
		}

		if (expectedPaths.All(p => !path.StartsWith(p, StringComparison.InvariantCultureIgnoreCase)))
		{
			throw new RequestParsingException("Unable to parse request, the wrong path was supplied {0}", path);
		}

		PathSegments = path.Split('/');
	}

	/// <summary>
	/// Throws if the parsing lambda is unable to successfully parse the values
	/// </summary>
	/// <typeparam name="TOutput">The type of the successfully parsed output.</typeparam>
	/// <param name="parseMethod">The parse method.</param>
	/// <returns>TOutput.</returns>
	/// <exception cref="RequestParsingException">Unable to parse request, unrecognized path segment</exception>
	protected TOutput ThrowIfUnsuccessfullyParsed<TOutput>(Func<(bool success, TOutput output)> parseMethod)
	{
		var (success, output) = parseMethod.Invoke();
		if (!success)
		{
			throw new RequestParsingException("Unable to parse request, unrecognized path segment");
		}
		return output;
	}
}
