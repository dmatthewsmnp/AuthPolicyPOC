using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Resolvers;
using AuthPolicyPOC.Examples;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthPolicyPOC.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{
	[HttpGet("pubping")] // This route should be allowed due to explicit AllowAnonymous
	[AllowAnonymous]
	public string PublicPing() => DateTime.Now.ToString();

	[HttpGet("privping")] // This route should get 401 due to no authorization type
	public string PrivatePing() => DateTime.Now.ToString();

	[HttpGet("{guid}/{name}")]
	[GuidRequirement(typeof(UriGuidResolver), typeof(GuidRecognizedRequirementHandler), "1")]
	public string GetOne(Guid guid, string name)
	{
		return $"Hello from one, {name}";
	}

	[HttpGet("one/{guid}/{name}")]
	[GuidRequirement(typeof(UriGuidResolver), typeof(GuidRecognizedRequirementHandler), "2")]
	public string GetTwo(Guid guid, string name)
	{
		return $"Hello from two, {name}";
	}

	[HttpPost("tempmodel")]
	[GuidRequirement(typeof(JsonBodyGuidResolver<TempModel>), typeof(GuidRecognizedRequirementHandler), "Id")]
	public string PostTemp([FromBody] TempModel model)
	{
		return $"Received TempModel {model.Id}:{model.SecondId}";
	}

	public class TempModel
	{
		public Guid? Id { get; set; }
		public Guid? SecondId { get; set; }
	}
}
