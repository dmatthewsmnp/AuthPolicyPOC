using AuthPolicyPOC.Policies.Bases;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Policies;

public class HasAccessToGuidHandler : BasedOnRequestAuthorizationHandler<HasAccessToGuidRequirement>
{
	private readonly ILogger<BasedOnRequestAuthorizationHandler<HasAccessToGuidRequirement>> _logger;

	public HasAccessToGuidHandler(ILogger<BasedOnRequestAuthorizationHandler<HasAccessToGuidRequirement>> logger) :
		base(logger)
	{
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, HasAccessToGuidRequirement requirement)
	{
		await base.HandleRequirementAsync(context, requirement);

		if (context.HasFailed)
		{
			return;
		}

		var paymentRequest = await requirement.GetPaymentCredentialRequirementAsync(HttpContext);
		if (paymentRequest == null)
		{
			_logger.LogDebug("User failed business access check. No access in DB.");
			context.Fail();
		}
		else
		{
			context.Succeed(requirement);
		}
	}
}