using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthPolicyPOC.Authorization;

/// <summary>
/// Handler for executing all authorization policies applied to Controller methods within this API
/// and rehydrated from ApiAuthorizationPolicyProvider
/// </summary>
public class ApiAuthorizationHandler : IAuthorizationHandler
{
	#region Fields and constructor
	private readonly ILogger _logger;
	public ApiAuthorizationHandler(ILogger<ApiAuthorizationHandler> logger) => _logger = logger;
	#endregion

	/// <summary>
	/// Authorization handler method: iterate through all pending requirements and validate
	/// </summary>
	public async Task HandleAsync(AuthorizationHandlerContext context)
	{
		if (context.PendingRequirements.Any() && !context.HasFailed)
		{
			// Retrieve HttpContext for this request:
			if (context.Resource is not HttpContext httpContext)
			{
				_logger.LogDebug("Failed to get HttpContext from resource {ResourceType}", context.Resource?.GetType()?.FullName ?? "(null)");
				context.Fail();
			}
			// Ensure claims are present in user token:
			else if (!(context.User?.Claims?.Any() ?? false))
			{
				_logger.LogDebug("No claims were found for the user.");
				context.Fail();
			}
			else
			{
				// Retrieve Guid identifier of logged-in user from claims:
				var userClaim = context.User.FindAll(ClaimTypes.NameIdentifier)
					.Select<Claim, Guid?>(c => Guid.TryParse(c.Value, out var guid) ? guid : null) // Convert valid claims to Guid
					.FirstOrDefault(guid => guid != null);
				if (userClaim == null)
				{
					_logger.LogDebug("No user name claim was found.");
					context.Fail();
				}
				else
				{
					#region Process pending requirements against user claims
					// Retrieve clientAccess claims (as list of Guids):
					var clientClaims = context.User.FindAll("clientAccess")?.Select(c => Guid.Parse(c.Value))?.ToList();

					// Iterate through pending requirements list, until one fails or all are successful:
					foreach (var requirement in context.PendingRequirements)
					{
						if (requirement is ResourceAuthorizationRequirement authRequirement)
						{
							// Expected requirement type - run requirement check and set result:
							if (await authRequirement.CheckRequirement(httpContext, clientClaims, userClaim))
							{
								context.Succeed(requirement);
							}
							else
							{
								context.Fail();
								break;
							}
						}
						else if (requirement is NotAuthorizedRequirement)
						{
							// Default decline policy - fail request silently:
							context.Fail();
							break;
						}
						else
						{
							// Unknown authorization requirement type - log warning and fail request:
							_logger.LogWarning("Unhandled requirement type: {RequirementType}", requirement.GetType().FullName);
							context.Fail();
							break;
						}
					}
					#endregion
				}
			}
		}
	}
}
