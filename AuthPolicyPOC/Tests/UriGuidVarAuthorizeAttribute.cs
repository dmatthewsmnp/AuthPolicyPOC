using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Tests;

public class UriGuidVarAuthorizeAttribute : AuthorizeAttribute
{
	public const string POLICY_PREFIX = "UriGuid_";

	public UriGuidVarAuthorizeAttribute(int uriPosition, Type guidAuthRequirement)
	{
		if (typeof(IGuidAuthRequirement).IsAssignableFrom(guidAuthRequirement))
		{
			Policy = $"{POLICY_PREFIX}{uriPosition}_{guidAuthRequirement.AssemblyQualifiedName}";
		}
		else
		{
			throw new ArgumentException("Invalid authorization requirement type", nameof(guidAuthRequirement));
		}
	}

	public static int GetPosition(string policyName)
	{
		var policySegments = policyName.Split("_");
		return policySegments.Length == 3 && int.TryParse(policySegments[1], out var position) ? position
			: throw new InvalidOperationException("Invalid policy string or Position not found");
	}

	public static Type GetRequirementType(string policyName)
	{
		var policySegments = policyName.Split("_");
		var requirementType = policySegments.Length == 3 ? Type.GetType(policySegments[2]) : null;
		return requirementType ?? throw new InvalidOperationException("Invalid policy string or Type not found");
	}
}
