using System.Collections.Generic;

namespace AuthPolicyPOC.Examples.Models;

public class AccessMapUpdateRequest
{
	/// <summary>
	/// Replacement list of entities able to access the payment credential
	/// </summary>
	public IEnumerable<EntityListEntry>? accessMap { get; set; } = null;
}
