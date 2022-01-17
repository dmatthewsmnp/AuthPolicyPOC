using System.Text.Json.Serialization;

namespace AuthPolicyPOC.Examples.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EntityTypeID
{
	MPMClient = 1,
	PortalUser = 2
};
