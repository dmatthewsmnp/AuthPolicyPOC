#nullable disable
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Policies.Bases;

/// <summary>
///     A base authorization handler that validates common scenarios and extracts claims from the incoming request
/// </summary>
/// <typeparam name="TRequirement">The type of the t requirement.</typeparam>
public abstract class BasedOnRequestAuthorizationHandler<TRequirement> : AuthorizationHandler<TRequirement>
	where TRequirement : IAuthorizationRequirement
{
	private readonly ILogger<BasedOnRequestAuthorizationHandler<TRequirement>> _logger;
	protected IEnumerable<Guid> ClientClaims;
	protected HttpContext HttpContext;
	protected Guid UserClaim;

	/// <inheritdoc />
	protected BasedOnRequestAuthorizationHandler(ILogger<BasedOnRequestAuthorizationHandler<TRequirement>> logger) => _logger = logger;

	/// <inheritdoc />
	protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement)
	{
		if (context.Resource is not HttpContext httpContext)
		{
			_logger.LogDebug(
				"Unknown authorization context resource: {1}",
				context.Resource?.GetType().FullName ?? "Null resource");
			context.Fail();
			return Task.CompletedTask;
		}

		if (!context.User.Claims.Any())
		{
			_logger.LogDebug("No claims were found for the user.");
			context.Fail();
			return Task.CompletedTask;
		}

		var userClaim = context.User.FindFirst(ClaimTypes.NameIdentifier);

		if (userClaim is null)
		{
			_logger.LogDebug("No user name claim was found.");
			context.Fail();
			return Task.CompletedTask;
		}

		ClientClaims = context.User.FindAll(Constants.ClientAccessClaimName).Select(c => Guid.Parse(c.Value));
		HttpContext = httpContext;
		UserClaim = Guid.Parse(userClaim.Value);
		return Task.CompletedTask;
	}
}