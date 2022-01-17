using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Tests;

public class UriGuidRequirement : IAuthorizationRequirement
{
	private readonly int _position;
	private readonly Type _requirementType;
	public UriGuidRequirement(string policyName)
	{
		_position = UriGuidVarAuthorizeAttribute.GetPosition(policyName);
		_requirementType = UriGuidVarAuthorizeAttribute.GetRequirementType(policyName);
	}

	public async Task<bool> Validate(HttpContext? context)
	{
		string? path = context?.Request?.Path;
		if (path?.StartsWith('/') ?? false)
		{
			var pathSegments = path[1..].Split('/'); // Skip leading '/'
			if (pathSegments.Length > _position && Guid.TryParse(pathSegments[_position], out var guid))
			{
				// Guid value retrieved from Uri; now try creating requirement object:
				var authRequirement = Activator.CreateInstance(_requirementType) as IGuidAuthRequirement;
				if (authRequirement != null)
				{
					return await authRequirement.IsAuthorized(guid);
				}
			}
		}
		return false;
	}
}