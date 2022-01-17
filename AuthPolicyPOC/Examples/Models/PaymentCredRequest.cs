using System.Collections.Generic;

namespace AuthPolicyPOC.Examples.Models;

public class PaymentCredRequest
{
	public CredTypeID credTypeID { get; set; } = CredTypeID.Invalid;
	public IEnumerable<EntityListEntry>? accessMap { get; set; } = null;
}
