using AuthPolicyPOC.Authorization.Requirements;

namespace AuthPolicyPOC.Examples;

// Example Guid requirement - value must be one of a specified set:
public class GuidRecognizedRequirementHandler : IRequirementHandler<Guid?>
{
	private readonly Guid[] _recognized = new[] {
		Guid.Parse("484FB935-ED46-EC11-B6BF-5CFF35DE36A1"),
		Guid.Parse("494FB935-ED46-EC11-B6BF-5CFF35DE36A1")
	};
	public Task<bool> CheckRequirement(Guid? resource, IEnumerable<Guid>? clientClaims, Guid? userClaim)
	{
		return Task.FromResult(resource != null && _recognized.Contains((Guid)resource));
	}
}
