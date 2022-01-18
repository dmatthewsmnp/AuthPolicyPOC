using System;
using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Resolvers;
using AuthPolicyPOC.Examples;
using AuthPolicyPOC.Examples.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthPolicyPOC.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{
	#region General (non-policy)
	[HttpGet("public/ping")] // This route should be allowed due to explicit AllowAnonymous
	[AllowAnonymous]
	public string PublicPing() => DateTime.Now.ToString();

	[HttpGet("private/ping")] // This route should get 401 due to no authorization type
	public string PrivatePing() => DateTime.Now.ToString();
	#endregion

	#region PaymentCreds
	/// <summary>
	/// Create a new payment credential
	/// </summary>
	/// <remarks>
	/// Since cred is being created no security on credential required, but user must have access to all entities in AccessMap;
	/// resolver will deserialize PaymentCredRequest from request body and pass to requirement handler
	/// </remarks>
	[HttpPost("paymentcred")]
	[ClassRequirement(classToResolve: typeof(PaymentCredRequest), classRequirementHandler: typeof(HasAccessToAllAccessMapEntitiesRequirementHandler))]
	public string PostPaymentCred([FromBody] PaymentCredRequest request)
	{
		return $"Created PaymentCred {request.credTypeID}";
	}

	/// <summary>
	/// Delete an existing payment credential
	/// </summary>
	/// <remarks>
	/// User must have access to update/delete this payment credential; resolver will extract PaymentCredGUID from route token 2
	/// </remarks>
	[HttpDelete("paymentcred/{PaymentCredGUID}")]
	[GuidRequirement(guidValueResolver: typeof(UriGuidResolver), resolverArg: "2", guidRequirementHandler: typeof(HasAccessToPaymentCredUpdateAndDeleteRequirementHandler))]
	public string DeletePaymentCred(Guid PaymentCredGUID)
	{
		return $"Deleted {PaymentCredGUID}";
	}

	/// <summary>
	/// Update access map on an existing payment credential
	/// </summary>
	/// <remarks>
	/// - User must have access to update/delete this payment credential; resolver will extract PaymentCredGUID from route token 2
	/// - User must have access to all entities in AccessMap; resolver will deserialize AccessMapUpdate from request body and pass to requirement handler
	/// </remarks>
	[HttpPost("paymentcred/{PaymentCredGUID}/AccessMapUpdate")]
	[GuidRequirement(guidValueResolver: typeof(UriGuidResolver), resolverArg: "2", guidRequirementHandler: typeof(HasAccessToPaymentCredUpdateAndDeleteRequirementHandler))]
	[ClassRequirement(typeof(AccessMapUpdateRequest), typeof(HasAccessToAllAccessMapEntitiesRequirementHandler))]
	public string PostAccessMapUpdate(Guid PaymentCredGUID, [FromBody] AccessMapUpdateRequest request)
	{
		return $"Updated AccessMap {PaymentCredGUID}";
	}

	/// <summary>
	/// Retrieve entities linked to the specified payment credential
	/// </summary>
	/// <remarks>
	/// User must have access to view this payment credential; resolver will extract PaymentCredGUID from route token 2
	/// </remarks>
	[HttpGet("paymentcred/{PaymentCredGUID}/Entities")]
	[GuidRequirement(guidValueResolver: typeof(UriGuidResolver), resolverArg: "2", guidRequirementHandler: typeof(HasAccessToPaymentCredRequirementHandler))]
	public string GetEntitiesByPaymentCred(Guid PaymentCredGUID)
	{
		return $"Entities retrieved {PaymentCredGUID}";
	}
	#endregion

	#region Payments
	/// <summary>
	/// Create payment
	/// </summary>
	/// <remarks>
	/// User must have access to this payment credential; resolver will deserialize PaymentRequest from request body and check access against paymentCredGUID property
	/// </remarks>
	[HttpPost("payment")]
	[GuidRequirement(guidValueResolver: typeof(JsonBodyGuidResolver<PaymentRequest>), resolverArg: "paymentCredGUID", guidRequirementHandler: typeof(HasAccessToPaymentCredRequirementHandler))]
	public string PostPayment([FromBody] PaymentRequest request)
	{
		return $"Created payment for ${request.amount}";
	}
	#endregion
}
