using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace AuthPolicyPOC.Authorization.Requirements;

/// <summary>
/// Interface for handler class, responsible for checking resource against user claims
/// </summary>
/// <typeparam name="T">Type of resource identifier object</typeparam>
public interface IRequirementHandler<T>
{
	/// <summary>
	/// Check access to "resource" using user claims
	/// </summary>
	/// <param name="resource">Identifier of resource being authorized</param>
	/// <param name="clientClaims">List of client Guids from token claims</param>
	/// <param name="userClaim">User identifier from token claims</param>
	/// <returns>True if authorization successful (request can proceed), false otherwise (request must fail)</returns>
	public Task<bool> CheckRequirement(T resource, IEnumerable<Guid>? clientClaims, Guid? userClaim);
}
