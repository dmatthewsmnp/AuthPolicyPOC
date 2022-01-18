using System;

namespace AuthPolicyPOC.Examples.Models;

public class PaymentRequest
{
	public Guid paymentCredGUID { get; set; }
	public decimal amount { get; set; }
}
