using AuthPolicyPOC.Exceptions;
using AuthPolicyPOC.Policies.Bases;

namespace AuthPolicyPOC.Policies;

/// <summary>
///     Provides the logic to extract the payment credential guid from incoming request
///     Implements the <see cref="BasedOnRequestAuthorizationRequirement" />
/// </summary>
/// <seealso cref="BasedOnRequestAuthorizationRequirement" />
public class HasAccessToGuidRequirement : BasedOnRequestAuthorizationRequirement
{
    /// <summary>
    ///     Gets the payment guid from the path or request body and returns it as the requirements necessary to authorize this
    ///     request
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns>Guid.</returns>
    /// <exception cref="RequestParsingException">Unexpected state</exception>
    /// <exception cref="RequestParsingException">Unable to parse JSON body</exception>
    public ValueTask<Guid?> GetPaymentCredentialRequirementAsync(HttpContext context)
    {
        return ValueTask.FromResult<Guid?>(context.Request.Method switch
        {
            "GET" => Guid.NewGuid(),
            "POST" => null,
            _ => throw new Exception("Unhandled request method")
        });
    }
}
