using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.Extensions.Logging;

namespace AuthPolicyPOC.Examples;

public class HasAccessToPaymentCredUpdateAndDeleteRequirementHandler : IRequirementHandler<Guid?>
{
	/// <summary>
	/// Simulate database returning list of payment creds attached to this PortalUser
	/// </summary>
	private readonly Guid[] _userOwnsPaymentCreds = new[] {
		Guid.Parse("484FB935-ED46-EC11-B6BF-5CFF35DE36A1"),
		Guid.Parse("494FB935-ED46-EC11-B6BF-5CFF35DE36A1")
	};

	private readonly ILogger _logger;
	public HasAccessToPaymentCredUpdateAndDeleteRequirementHandler(ILogger<HasAccessToPaymentCredUpdateAndDeleteRequirementHandler> logger)
		=> _logger = logger;

	/// <summary>
	/// Ensure user has access to update/delete a specific PaymentCredGUID
	/// </summary>
	/// <param name="resource">PaymentCredGUID being requested</param>
	/// <param name="clientClaims">List of clients accessible to user (not relevant for this request)</param>
	/// <param name="userClaim">ID of requesting user</param>
	/// <returns></returns>
	public Task<bool> CheckRequirement(Guid? resource, IEnumerable<Guid>? clientClaims, Guid? userClaim)
	{
		bool result = false;
		if (resource == null)
		{
			_logger.LogDebug("No PaymentCredGUID provided, rejecting request");
		}
		else if (_userOwnsPaymentCreds.Contains((Guid)resource))
		{
			result = true;
		}
		else
		{
			_logger.LogDebug("PaymentCredGUID {PaymentCredGUID} not attached to PortalUser {PortalUser}, rejecting request", resource, userClaim);
		}
		return Task.FromResult(result);
	}
}
