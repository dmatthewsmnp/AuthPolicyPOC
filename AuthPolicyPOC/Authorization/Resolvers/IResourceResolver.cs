using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AuthPolicyPOC.Authorization.Resolvers;

/// <summary>
/// Interface for class responsible for resolving (from request context) the resource being
/// protected by an authorization policy
/// </summary>
public interface IResourceResolver<T>
{
	/// <summary>
	/// Retrieve resource from request context (from Uri, request body, etc)
	/// </summary>
	public Task<T> ResolveResource(HttpContext? context);
}
