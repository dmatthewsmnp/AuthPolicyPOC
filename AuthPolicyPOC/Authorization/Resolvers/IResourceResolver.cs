namespace AuthPolicyPOC.Authorization.Resolvers;

/// <summary>
/// Interface for class responsible for retrieving the identifier of the resource being protected
/// by authorization policy from request context
/// </summary>
public interface IResourceResolver<T>
{
	/// <summary>
	/// Retrieve resource identifier from request context (from Uri, request body, etc)
	/// </summary>
	public Task<T> ResolveResource(HttpContext? context);
}
