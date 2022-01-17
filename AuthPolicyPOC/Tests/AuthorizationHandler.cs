using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Tests;

public class AuthorizationHandler : IAuthorizationHandler
{
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        var pendingRequirements = context.PendingRequirements.ToList();

        foreach (var requirement in pendingRequirements)
        {
            if (requirement is UriGuidRequirement uriGuid)
            {
                if (await uriGuid.Validate(context.Resource as HttpContext))
                {
                    context.Succeed(requirement);
                }
                else
                {
                    Console.WriteLine($"Requirement {requirement} failed");
                    context.Fail();
                }
            }
            else
            {
                Console.WriteLine($"Unhandled requirement type: {requirement}");
                context.Fail();
            }
        }
    }
}
