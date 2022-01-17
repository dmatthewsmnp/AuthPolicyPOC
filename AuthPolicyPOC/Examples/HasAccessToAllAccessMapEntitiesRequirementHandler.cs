using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Examples.Models;
using Microsoft.Extensions.Logging;

namespace AuthPolicyPOC.Examples;

public class HasAccessToAllAccessMapEntitiesRequirementHandler : IRequirementHandler<object?>
{
	private readonly ILogger _logger;
	public HasAccessToAllAccessMapEntitiesRequirementHandler(ILogger<HasAccessToAllAccessMapEntitiesRequirementHandler> logger)
		=> _logger = logger;

	/// <summary>
	/// Ensure user has access to update/delete a specific PaymentCredGUID
	/// </summary>
	/// <param name="resource">PaymentCredGUID being requested</param>
	/// <param name="clientClaims">List of clients accessible to user (not relevant for this request)</param>
	/// <param name="userClaim">ID of requesting user</param>
	/// <returns></returns>
	public Task<bool> CheckRequirement(object? resource, IEnumerable<Guid>? clientClaims, Guid? userClaim)
	{
		#region Extract accessMap from request object based on type
		IEnumerable<EntityListEntry>? accessMap = null;
		if (resource == null)
		{
			_logger.LogDebug("No request object provided, rejecting request");
			return Task.FromResult(false);
		}
		else if (resource is AccessMapUpdateRequest accessMapRequest)
		{
			accessMap = accessMapRequest.accessMap;
			if (accessMap == null)
			{
				_logger.LogDebug("Received AccessMapUpdateRequest with empty access map");
			}
		}
		else if (resource is PaymentCredRequest paymentCredRequest)
		{
			accessMap = paymentCredRequest.accessMap;
			if (accessMap == null)
			{
				_logger.LogDebug("Received PaymentCredRequest with empty access map");
			}
		}
		else
		{
			_logger.LogDebug("Incorrect class type received, rejecting request");
		}
		#endregion

		bool result = false;
		if (accessMap != null)
		{
			// Ensure that all entries in accessMap are included in user's claims:
			result = accessMap.All(amentry =>
				(amentry.entityType == EntityTypeID.MPMClient && (clientClaims?.Contains(amentry.entityGUID) ?? false))
				|| (amentry.entityType == EntityTypeID.PortalUser && amentry.entityGUID == userClaim)
			);
			if (!result)
			{
				_logger.LogWarning("Received accessMap with invalid values"); // Potential security issue, shouldn't be possible
			}
		}
		return Task.FromResult(result);
	}
}
