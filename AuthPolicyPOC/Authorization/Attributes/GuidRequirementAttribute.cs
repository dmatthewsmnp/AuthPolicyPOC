using System;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AuthPolicyPOC.Authorization.Attributes;

/// <summary>
/// Attribute for applying authorization policy against a resource identified by a Guid value
/// </summary>
public class GuidRequirementAttribute : AuthorizeAttribute
{
	/// <summary>
	/// Leading string for identifying an authorization policy of this type
	/// </summary>
	public const string POLICY_PREFIX = "GuidRequirement_";

	/// <summary>
	/// Public constructor
	/// </summary>
	/// <param name="guidValueResolver">A type of IResourceResolver able to retrieve a Guid from request context</param>
	/// <param name="guidRequirementHandler">A type of IRequirementHandler able to enforce policy against a resource identified by Guid</param>
	/// <param name="resolverArg">Optional argument to be passed to guidValueResolver</param>
	public GuidRequirementAttribute(Type guidValueResolver, Type guidRequirementHandler, string? resolverArg = null)
	{
		// Validate types, and ensure that casting at authorization time will be possible:
		if (!typeof(IResourceResolver<Guid?>).IsAssignableFrom(guidValueResolver))
		{
			throw new ArgumentException("Invalid resource resolver type", nameof(guidValueResolver));
		}
		else if (!typeof(IRequirementHandler<Guid?>).IsAssignableFrom(guidRequirementHandler))
		{
			throw new ArgumentException("Invalid requirement handler type", nameof(guidRequirementHandler));
		}
		else
		{
			// Construct base class Policy name string from prefix, resolver and handler types, and optional argument(s):
			Policy = $"{POLICY_PREFIX}{guidValueResolver.AssemblyQualifiedName}_{guidRequirementHandler.AssemblyQualifiedName}_{resolverArg}";
		}
	}

	#region Static utility methods
	/// <summary>
	/// Construct AuthorizationRequirement object with resolver and handler specified by policyName string
	/// </summary>
	public static AuthorizationRequirement<Guid?> GetAuthorizationRequirement(IServiceProvider isp, string policyName)
	{
		var policySegments = policyName.Split("_");
		if (policySegments.Length == 4)
		{
			var resolverType = Type.GetType(policySegments[1], false, true);
			var requirementType = Type.GetType(policySegments[2], false, true);
			if (resolverType != null && requirementType != null)
			{
				return new AuthorizationRequirement<Guid?>(
					policyName: POLICY_PREFIX[..^1],
					resourceResolver: ActivatorUtilities.CreateInstance(isp, resolverType, policySegments[3]) as IResourceResolver<Guid?>,
					requirementHandler: ActivatorUtilities.CreateInstance(isp, requirementType) as IRequirementHandler<Guid?>);
			}
		}

		// If any part of policy string failed to parse above, throw error:
		throw new InvalidOperationException("Invalid policy string");
	}
	#endregion
}
