using System;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AuthPolicyPOC.Authorization.Attributes;

/// <summary>
/// Attribute for applying authorization policy against a class object deserialized from request body
/// </summary>
public class ClassRequirementAttribute : AuthorizeAttribute
{
	/// <summary>
	/// Leading string for identifying an authorization policy of this type
	/// </summary>
	/// <param name="="
	public const string POLICY_PREFIX = "ClassRequirement_";

	/// <summary>
	/// Public constructor
	/// </summary>
	/// <param name="classToResolve">Type to be deserialized from request body</param>
	/// <param name="classRequirementHandler">Type of IRequirementHandler able to enforce policy against an object of type classToResolve</param>
	/// <exception cref="ArgumentException"></exception>
	public ClassRequirementAttribute(Type classToResolve, Type classRequirementHandler)
	{
		// Validate types, and ensure that casting at authorization time will be possible:
		if (classToResolve.IsValueType)
		{
			throw new ArgumentException("Invalid Type for requirement (must be a class type)", nameof(classToResolve));
		}
		else if (!typeof(IRequirementHandler<object?>).IsAssignableFrom(classRequirementHandler))
		{
			throw new ArgumentException("Invalid requirement handler type", nameof(classRequirementHandler));
		}
		else
		{
			// Construct base class Policy name string from prefix, resolver and handler types, and optional argument(s):
			Policy = $"{POLICY_PREFIX}{classToResolve.AssemblyQualifiedName}_{classRequirementHandler.AssemblyQualifiedName}";
		}
	}

	#region Static utility methods
	/// <summary>
	/// Construct AuthorizationRequirement object with resolver and handler specified by policyName string
	/// </summary>
	public static AuthorizationRequirement<object?> GetAuthorizationRequirement(IServiceProvider isp, string policyName)
	{
		var policySegments = policyName.Split("_");
		if (policySegments.Length == 3)
		{
			var classType = Type.GetType(policySegments[1], false, true);
			var requirementType = Type.GetType(policySegments[2], false, true);
			if (classType != null && requirementType != null)
			{
				return new AuthorizationRequirement<object?>(
					policyName: POLICY_PREFIX[..^1],
					resourceResolver: ActivatorUtilities.CreateInstance<JsonBodyClassResolver>(isp, classType),
					requirementHandler: ActivatorUtilities.CreateInstance(isp, requirementType) as IRequirementHandler<object?>);
			}
		}

		// If any part of policy string failed to parse above, throw error:
		throw new InvalidOperationException("Invalid policy string");
	}
	#endregion
}
