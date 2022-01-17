using System;

namespace AuthPolicyPOC.Examples.Models;

public class EntityListEntry
{
	/// <summary>
	/// Type of entity
	/// </summary>
	public EntityTypeID entityType { get; set; }

	/// <summary>
	/// Unique identifier for this Entity in client system
	/// </summary>
	public Guid entityGUID { get; set; }

	/// <summary>
	/// Optional flag for whether this entity considers this credential to be their default payment option
	/// </summary>
	public bool isDefault { get; set; } = false;
}
