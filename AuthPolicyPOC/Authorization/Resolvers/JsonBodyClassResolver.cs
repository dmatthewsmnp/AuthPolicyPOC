using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AuthPolicyPOC.Authorization.Resolvers;

/// <summary>
/// Resolver to deserialize an object of the specified class type from request body
/// </summary>
public class JsonBodyClassResolver : IResourceResolver<object?>
{
	#region Fields and constructor
	private readonly Type _classType;
	public JsonBodyClassResolver(Type classType) => _classType = classType;
	#endregion

	public async Task<object?> ResolveResource(HttpContext? context)
	{
		if (context?.Request != null && context.Request.ContentType == "application/json")
		{
			// Enable buffering of data in request stream and read entire contents:
			context.Request.EnableBuffering();
			using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
			var bodyContent = await reader.ReadToEndAsync();

			// Reset position of request body stream and discard buffered data:
			context.Request.Body.Position = 0;
			reader.DiscardBufferedData();

			try
			{
				// Attempt to deserialize incoming data into specified type:
				return JsonSerializer.Deserialize(bodyContent, _classType);
			}
			catch (JsonException)
			{
				return null;
			}
		}

		// Request not available or unexpected content type:
		return null;
	}

	#region Internal properties (for test access)
	internal Type ClassType
	{
		get
		{
			return _classType;
		}
	}
	#endregion
}
