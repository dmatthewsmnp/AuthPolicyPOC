using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Authorization.Requirements;

/// <summary>
/// Abstract base class for AuthorizationRequirement
/// </summary>
public abstract class AuthorizationRequirement : IAuthorizationRequirement
{
	/// <summary>
	/// Descriptor for this requirement or handler (for logging purposes)
	/// </summary>
	public abstract string RequirementDescriptor
	{
		get;
	}

	/// <summary>
	/// Requirement check method: use resolver to locate resource identifier, use handler to enforce authorization policy
	/// </summary>
	/// <param name="context">HttpContext of curent request (use to locate resource identifier)</param>
	/// <param name="clientClaims">Any client claims provided in user's authentication token</param>
	/// <param name="userClaim">User identifier provided in user's authentication token</param>
	/// <returns>True if request was successfully authorized, false otherwise</returns>
	public abstract Task<bool> CheckRequirement(HttpContext? context, IEnumerable<Guid>? clientClaims, Guid? userClaim);
}

/// <summary>
/// Concrete AuthorizationRequirement class, taking generic type parameter
/// </summary>
/// <typeparam name="T">Type of resource identifier which will be resolved from request and checked by handler</typeparam>
public class AuthorizationRequirement<T> : AuthorizationRequirement, IAuthorizationRequirement
{
	#region Fields and constructor
	private readonly IResourceResolver<T?> _resourceResolver;
	private readonly IRequirementHandler<T?> _requirementHandler;
	private readonly string _policyName;

	/// <summary>
	/// Public constructor
	/// </summary>
	/// <param name="resourceResolver">Resolver object able to locate resource identifier from request context</param>
	/// <param name="requirementHandler">Handler object able to enforce access policy against resource</param>
	/// <exception cref="ArgumentNullException"></exception>
	public AuthorizationRequirement(string policyName, IResourceResolver<T?>? resourceResolver, IRequirementHandler<T?>? requirementHandler)
	{
		_resourceResolver = resourceResolver ?? throw new ArgumentNullException(nameof(resourceResolver));
		_requirementHandler = requirementHandler ?? throw new ArgumentNullException(nameof(requirementHandler));
		_policyName = policyName;
	}
	#endregion

	/// <summary>
	/// RequirementDescriptor property implementation
	/// </summary>
	public override string RequirementDescriptor
	{
		get
		{
			return _requirementHandler?.GetType().FullName ?? _policyName;
		}
	}

	/// <summary>
	/// Requirement check method implementation
	/// </summary>
	public override async Task<bool> CheckRequirement(HttpContext? context, IEnumerable<Guid>? clientClaims, Guid? userClaim)
	{
		return await _requirementHandler.CheckRequirement(await _resourceResolver.ResolveResource(context), clientClaims, userClaim);
	}
}
