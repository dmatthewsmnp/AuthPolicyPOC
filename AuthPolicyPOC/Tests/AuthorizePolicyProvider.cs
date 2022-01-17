using AuthPolicyPOC.Policies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Tests;

public class AuthorizePolicyProvider : IAuthorizationPolicyProvider
{
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.Equals(PolicyNames.HasAccessToPaymentCredentials, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<AuthorizationPolicy?>(
                new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .AddRequirements(new HasAccessToGuidRequirement())
                    .Build());
        }
        else if (policyName.StartsWith(UriGuidVarAuthorizeAttribute.POLICY_PREFIX, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<AuthorizationPolicy?>(
                new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .AddRequirements(new UriGuidRequirement(policyName))
                    .Build());
        }
        return Task.FromResult<AuthorizationPolicy?>(null!);
    }

	Task<AuthorizationPolicy> IAuthorizationPolicyProvider.GetDefaultPolicyAsync()
	{
        return Task.FromResult(new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme).AddRequirements(new NotAuthorizedRequirement()).Build());
    }

	Task<AuthorizationPolicy?> IAuthorizationPolicyProvider.GetFallbackPolicyAsync()
	{
        return Task.FromResult<AuthorizationPolicy?>(null);
	}
}
