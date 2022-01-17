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
/// Handler for all authorization policies applied to Controller methods within this API
/// </summary>
public class AuthorizationHandler : IAuthorizationHandler
{
	#region Fields and constructor
	private readonly ILogger _logger;
	public AuthorizationHandler(ILogger<AuthorizationHandler> logger) => _logger = logger;
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
			else if (!(httpContext.User?.Claims?.Any() ?? false))
			{
				_logger.LogDebug("No claims were found for the user.");
				context.Fail();
			}
			// Ensure logged-in user claim (as Guid) is available:
			else if (!Guid.TryParse(httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var userClaim))
			{
				_logger.LogDebug("No user name claim was found.");
				context.Fail();
			}
			else
			{
				#region Process pending requirements against user claims
				// Retrieve clientAccess claims (as list of Guids):
				var clientClaims = context.User.FindAll("clientAccess")?.Select(c => Guid.Parse(c.Value));

				// Iterate through pending requirements list, until one fails or all are successful:
				foreach (var requirement in context.PendingRequirements)
				{
					if (requirement is AuthorizationRequirement authRequirement)
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
