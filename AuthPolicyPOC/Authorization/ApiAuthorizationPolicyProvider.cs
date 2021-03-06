using System;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Authorization;

/// <summary>
/// Provider for constructing AuthorizationPolicy objects at request time by rehydrating
/// data from authorization attribute policy strings
/// </summary>
public class ApiAuthorizationPolicyProvider : IAuthorizationPolicyProvider
{
	#region Fields and properties
	private readonly IServiceProvider _serviceProvider;
	public ApiAuthorizationPolicyProvider(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;
	#endregion

	/// <summary>
	/// Create authorization requirement object from policyName, use to construct AuthorizationPolicy
	/// </summary>
	public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
	{
		IAuthorizationRequirement? requirement = null;

		#region Create requirement from policyName
		if (policyName.StartsWith(AuthorizeByGuidAttribute.POLICY_PREFIX, StringComparison.OrdinalIgnoreCase))
		{
			requirement = AuthorizeByGuidAttribute.GetAuthorizationRequirement(_serviceProvider, policyName);
		}
		else if (policyName.StartsWith(AuthorizeByClassAttribute.POLICY_PREFIX, StringComparison.OrdinalIgnoreCase))
		{
			requirement = AuthorizeByClassAttribute.GetAuthorizationRequirement(_serviceProvider, policyName);
		}
		// NOTE: Place handlers for other policyName/RequirementAttribute pairs here as needed...
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
