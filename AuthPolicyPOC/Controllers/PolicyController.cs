using AuthPolicyPOC.Policies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthPolicyPOC.Controllers;
[Route("[controller]")]
[ApiController]
public class PolicyController : ControllerBase
{
	private readonly ILogger _logger;
	public PolicyController(ILogger<PolicyController> logger)
	{
		_logger = logger;
	}

	[HttpGet("gethello/{name}")]
	[HttpPost("gethello/{name}")]
	[HttpPatch("gethello/{name}")]
	[Authorize(Policy = PolicyNames.HasAccessToPaymentCredentials)]
	public string Do(string name)
	{
		return $"Hello {name}";
	}
}
