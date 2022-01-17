namespace AuthPolicyPOC.Policies;

public static class Constants
{
	public const string ClientAccessClaimName = "clientAccess";
}

public static class PolicyNames
{
	public const string HasAccessToFeed = "HassAccessToFeed";
	public const string HasAccessToPaymentCredentials = "HasAccessToPaymentCredentials";
	public const string NotAuthorized = "NotAuthorized";
	public const string HasAccessToClientPaymentGuids = "HasAccessToClientPaymentGuids";
	public const string HasAccessToAllAccessMapEntities = "HasAccessToAllAccessMapEntities";
}
