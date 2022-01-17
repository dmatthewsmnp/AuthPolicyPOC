﻿using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Authorization;

/// <summary>
/// Provider for constructing AuthorizationPolicies from policy names at request time
/// </summary>
public class AuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
	/// <summary>
	/// Create authorization requirement object from policyName, use to construct AuthorizationPolicy
	/// </summary>
	public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
	{
		IAuthorizationRequirement? requirement = null;

		#region Create requirement from policyName
		if (policyName.StartsWith(GuidRequirementAttribute.POLICY_PREFIX, StringComparison.OrdinalIgnoreCase))
		{
			requirement = GuidRequirementAttribute.GetAuthorizationRequirement(policyName);
		}
		// TODO: Place handlers for other policy types...
		#endregion

		// Construct AuthorizationPolicy from requirement (if requirement was not set, will use default policy)
		return Task.FromResult<AuthorizationPolicy?>(BuildPolicy(requirement));
	}

	/// <summary>
	/// Create default AuthorizationPolicy
	/// </summary>
	public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
	{
		return Task.FromResult(BuildPolicy());
	}

	/// <summary>
	/// Create fallback authorization policy
	/// </summary>
	public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
	{
		return Task.FromResult<AuthorizationPolicy?>(BuildPolicy());
	}

	#region Private utility methods
	/// <summary>
	/// Construct authorization policy object from requirement
	/// </summary>
	/// <remarks>
	/// If requirement not specified, use default NotAuthorizedRequirement to prevent access to resource
	/// </remarks>
	private static AuthorizationPolicy BuildPolicy(IAuthorizationRequirement? requirement = null)
	{
		return new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
			.AddRequirements(requirement ?? new NotAuthorizedRequirement())
			.Build();
	}
	#endregion
}
