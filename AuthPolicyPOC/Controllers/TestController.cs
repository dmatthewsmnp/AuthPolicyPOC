using AuthPolicyPOC.Tests;
using Microsoft.AspNetCore.Mvc;

namespace AuthPolicyPOC.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{
	[HttpGet("{guid}/{name}")]
	[UriGuidVarAuthorize(1, typeof(RecognizedGuidAuthRequirement))]
	public string GetOne(Guid guid, string name)
	{
		return $"Hello from one, {name}";
	}

	[HttpGet("one/{guid}/{name}")]
	[UriGuidVarAuthorize(2, typeof(RecognizedGuidAuthRequirement))]
	public string GetTwo(Guid guid, string name)
	{
		return $"Hello from two, {name}";
	}
}
