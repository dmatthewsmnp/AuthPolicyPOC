using System;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AuthPolicyPOC.Authorization.Attributes;

/// <summary>
/// Attribute for an authorization policy to be applied against a class object deserialized from request body
/// </summary>
public class AuthorizeByClassAttribute : AuthorizeAttribute
{
	/// <summary>
	/// Leading string for identifying an authorization policy of this type
	/// </summary>
	public const string POLICY_PREFIX = "ClassRequirement_|_";

	/// <summary>
	/// Public constructor
	/// </summary>
	/// <param name="classToResolve">Type to be deserialized from request body (must be a reference type)</param>
	/// <param name="classRequirementHandler">Type of IRequirementHandler able to enforce policy against an object of type classToResolve</param>
	/// <remarks>
	/// When C#10 supports generic attributes (in preview only at development time), Type parameters here can be moved to generic arguments
	/// </remarks>
	public AuthorizeByClassAttribute(Type classToResolve, Type classRequirementHandler)
	{
		// Validate types, and ensure that casting at authorization time will be possible:
		if (classToResolve.IsValueType)
		{
			throw new ArgumentException("Invalid Type for requirement (must be a reference type)", nameof(classToResolve));
		}
		else if (!typeof(IRequirementHandler<object?>).IsAssignableFrom(classRequirementHandler))
		{
			throw new ArgumentException("Invalid requirement handler type", nameof(classRequirementHandler));
		}
		else
		{
			// Construct base class Policy name string from prefix, resolver and handler types:
			Policy = $"{POLICY_PREFIX}{classToResolve.AssemblyQualifiedName}_|_{classRequirementHandler.AssemblyQualifiedName}";
		}
	}

	#region Static utility methods
	/// <summary>
	/// Construct ResourceAuthorizationRequirement object with resolver and handler specified by policyName string
	/// </summary>
	public static ResourceAuthorizationRequirement<object?> GetAuthorizationRequirement(IServiceProvider isp, string policyName)
	{
		var policySegments = policyName.Split("_|_");
		if (policySegments.Length == 3)
		{
			var classToResolve = Type.GetType(policySegments[1], false, true);
			var classRequirementHandler = Type.GetType(policySegments[2], false, true);
			if (classToResolve != null && classRequirementHandler != null)
			{
				return new ResourceAuthorizationRequirement<object?>(
					resourceResolver: ActivatorUtilities.CreateInstance<JsonBodyClassResolver>(isp, classToResolve),
					requirementHandler: ActivatorUtilities.CreateInstance(isp, classRequirementHandler) as IRequirementHandler<object?>);
			}
		}

		// If any part of policy string failed to parse above, throw error:
		throw new InvalidOperationException("Invalid policy string");
	}
	#endregion
}
