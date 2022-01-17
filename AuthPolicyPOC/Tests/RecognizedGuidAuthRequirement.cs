namespace AuthPolicyPOC.Tests;

public class RecognizedGuidAuthRequirement : IGuidAuthRequirement
{
	private readonly Guid[] _recognized = new[] {
		Guid.Parse("484FB935-ED46-EC11-B6BF-5CFF35DE36A1"),
		Guid.Parse("494FB935-ED46-EC11-B6BF-5CFF35DE36A1")
	};
	public Task<bool> IsAuthorized(Guid guid)
	{
		return Task.FromResult(_recognized.Contains(guid));
	}
}
