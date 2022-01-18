using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AuthPolicyPOC.Authorization.Requirements;

/// <summary>
/// Abstract base class for ResourceAuthorizationRequirement (dynamic resource authorization requirement checker)
/// </summary>
public abstract class ResourceAuthorizationRequirement : IAuthorizationRequirement
{
	/// <summary>
	/// Requirement check method: use resolver to locate resource in request context, use handler to enforce authorization policy
	/// </summary>
	/// <param name="context">HttpContext of curent request (used to locate resource)</param>
	/// <param name="clientClaims">Any client claims provided in user's authentication token</param>
	/// <param name="userClaim">User identifier provided in user's authentication token</param>
	/// <returns>True if request was successfully authorized, false otherwise</returns>
	public abstract Task<bool> CheckRequirement(HttpContext? context, List<Guid>? clientClaims, Guid? userClaim);
}

/// <summary>
/// Concrete ResourceAuthorizationRequirement class, taking generic type parameter
/// </summary>
/// <typeparam name="T">Type of resource which will be resolved from request and checked by handler</typeparam>
public class ResourceAuthorizationRequirement<T> : ResourceAuthorizationRequirement, IAuthorizationRequirement
{
	#region Fields and constructor
	private readonly IResourceResolver<T?> _resourceResolver;
	private readonly IRequirementHandler<T?> _requirementHandler;

	/// <summary>
	/// Public constructor
	/// </summary>
	/// <param name="resourceResolver">Resolver object able to locate resource from request context</param>
	/// <param name="requirementHandler">Handler object able to enforce access policy against resource</param>
	public ResourceAuthorizationRequirement(IResourceResolver<T?>? resourceResolver, IRequirementHandler<T?>? requirementHandler)
	{
		_resourceResolver = resourceResolver ?? throw new ArgumentNullException(nameof(resourceResolver));
		_requirementHandler = requirementHandler ?? throw new ArgumentNullException(nameof(requirementHandler));
	}
	#endregion

	/// <summary>
	/// Requirement check method implementation
	/// </summary>
	public override async Task<bool> CheckRequirement(HttpContext? context, List<Guid>? clientClaims, Guid? userClaim)
	{
		return await _requirementHandler.CheckRequirement(await _resourceResolver.ResolveResource(context), clientClaims, userClaim);
	}
}
