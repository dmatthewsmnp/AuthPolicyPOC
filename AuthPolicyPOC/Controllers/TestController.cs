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
	#region General
	[HttpGet("pubping")] // This route should be allowed due to explicit AllowAnonymous
	[AllowAnonymous]
	public string PublicPing() => DateTime.Now.ToString();

	[HttpGet("privping")] // This route should get 401 due to no authorization type
	public string PrivatePing() => DateTime.Now.ToString();
	#endregion

	#region PaymentCreds
	[HttpPost("paymentcred")]
	[ClassRequirement(typeof(PaymentCredRequest), typeof(HasAccessToAllAccessMapEntitiesRequirementHandler))]
	public string PostPaymentCred([FromBody] PaymentCredRequest request)
	{
		return $"Created PaymentCred {request.credTypeID}";
	}


	[HttpDelete("paymentcred/{PaymentCredGUID}")]
	[GuidRequirement(typeof(UriGuidResolver), typeof(HasAccessToPaymentCredUpdateAndDeleteRequirementHandler), "2")]
	public string DeletePaymentCred(Guid PaymentCredGUID)
	{
		return $"Deleted {PaymentCredGUID}";
	}

	[HttpPost("paymentcred/{PaymentCredGUID}/AccessMapUpdate")]
	[GuidRequirement(typeof(UriGuidResolver), typeof(HasAccessToPaymentCredUpdateAndDeleteRequirementHandler), "2")]
	[ClassRequirement(typeof(AccessMapUpdateRequest), typeof(HasAccessToAllAccessMapEntitiesRequirementHandler))]
	public string PostAccessMapUpdate(Guid PaymentCredGUID, [FromBody] AccessMapUpdateRequest request)
	{
		return $"Updated AccessMap {PaymentCredGUID}";
	}
	#endregion

	#region Guid from request model
	public class ModelWithGuidOne
	{
		public Guid? Id { get; set; }
		public Guid? SecondId { get; set; }
	}
	public class ModelWithGuidTwo
	{
		public Guid? ResourceId { get; set; }
	}

	[HttpPost("modelwithguidone")]
	[GuidRequirement(guidValueResolver: typeof(JsonBodyGuidResolver<ModelWithGuidOne>), guidRequirementHandler: typeof(GuidRecognizedRequirementHandler), resolverArg: "Id")]
	public string PostModelWithGuidOne([FromBody] ModelWithGuidOne model)
	{
		return $"Received ModelWithGuidOne {model.Id}:{model.SecondId}";
	}

	[HttpPost("modelwithguidtwo")]
	[GuidRequirement(guidValueResolver: typeof(JsonBodyGuidResolver<ModelWithGuidTwo>), guidRequirementHandler: typeof(GuidRecognizedRequirementHandler), resolverArg: "ResourceId")]
	public string PostModelWithGuidTwo([FromBody] ModelWithGuidTwo model)
	{
		return $"Received ModelWithGuidTwo {model.ResourceId}";
	}
	#endregion
}
