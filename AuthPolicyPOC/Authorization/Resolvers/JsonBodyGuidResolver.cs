using System;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AuthPolicyPOC.Authorization.Resolvers;

/// <summary>
/// Resolver to extract a Guid value from a member property of a class deserialized from JSON request body
/// </summary>
/// <typeparam name="T">Type into which request body should be deserialized</typeparam>
/// <remarks>
/// Requires a constructor argument specifying the property name from which Guid value can be extracted
/// </remarks>
public class JsonBodyGuidResolver<T> : IResourceResolver<Guid?> where T : class
{
	#region Fields and constructor
	private readonly PropertyInfo _propertyInfo;
	public JsonBodyGuidResolver(string fieldname)
	{
		_propertyInfo = typeof(T).GetProperty(fieldname ?? throw new ArgumentNullException(nameof(fieldname)))
			?? throw new ArgumentException($"{fieldname} is not a property of {typeof(T).FullName}", nameof(fieldname));
		if (_propertyInfo.PropertyType != typeof(Guid) && _propertyInfo.PropertyType != typeof(Guid?))
		{
			throw new ArgumentException($"{typeof(T).FullName}.{fieldname} is not a Guid", nameof(fieldname));
		}
	}
	#endregion

	public async Task<Guid?> ResolveResource(HttpContext? context)
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

			// Attempt to deserialize incoming data into specified type:
			try
			{
				var requestModel = JsonSerializer.Deserialize<T>(bodyContent);
				if (requestModel != null)
				{
					return _propertyInfo.GetValue(requestModel) as Guid?;
				}
			}
			catch (JsonException)
			{
				return null;
			}
		}

		// Request not available, unexpected content type or body could not be deserialized:
		return null;
	}

	#region Internal properties (for test access)
	internal string Property
	{
		get
		{
			return _propertyInfo.Name;
		}
	}
	#endregion
}
