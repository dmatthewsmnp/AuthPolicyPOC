using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.Extensions.Logging;

namespace AuthPolicyPOC.Examples;

// Example Guid requirement - value must be one of a specified set:
public class GuidRecognizedRequirementHandler : IRequirementHandler<Guid?>
{
	private readonly Guid[] _recognized = new[] {
		Guid.Parse("484FB935-ED46-EC11-B6BF-5CFF35DE36A1"),
		Guid.Parse("494FB935-ED46-EC11-B6BF-5CFF35DE36A1")
	};
	private readonly ILogger _logger;
	public GuidRecognizedRequirementHandler(ILogger<GuidRecognizedRequirementHandler> logger) => _logger = logger;

	public Task<bool> CheckRequirement(Guid? resource, IEnumerable<Guid>? clientClaims, Guid? userClaim)
	{
		bool result = false;
		if (resource == null)
		{
			_logger.LogDebug("No resource ID provided, rejecting request");
		}
		else if (_recognized.Contains((Guid)resource))
		{
			result = true;
		}
		else
		{
			_logger.LogDebug("Unrecognized resource ID provided, rejecting request");
		}
		return Task.FromResult(result);
	}
}
