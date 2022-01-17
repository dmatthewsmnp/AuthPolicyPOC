using Microsoft.AspNetCore.Authorization;

namespace AuthPolicyPOC.Authorization.Requirements;

/// <summary>
///  Marker requirement for a requirement which should always fail
/// </summary>
public class NotAuthorizedRequirement : IAuthorizationRequirement
{
}
