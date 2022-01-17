namespace AuthPolicyPOC.Tests;

public interface IGuidAuthRequirement
{
	public Task<bool> IsAuthorized(Guid guid);
}
