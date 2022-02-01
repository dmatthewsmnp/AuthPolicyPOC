using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace AuthPolicyPOC.Authorization.Resolvers;

/// <summary>
/// Resolver to extract a Guid value from request Uri/route
/// </summary>
/// <remarks>
/// Requires a constructor argument specifying zero-based position in Uri where Guid value will be
/// found; for example, in route "/api/ctrllername/resource/{guid}", the {guid} value is located at
/// position 3 (remember that controller name may be part of route)
/// </remarks>
public class UriGuidResolver : IResourceResolver<Guid?>
{
	#region Fields and constructor
	private readonly int _position;
	public UriGuidResolver(string position)
	{
		if ((int.TryParse(position, out _position) ? _position : -1) < 0)
		{
			throw new ArgumentOutOfRangeException(nameof(position));
		}
	}
	#endregion

	public Task<Guid?> ResolveResource(HttpContext? context)
	{
		// Extract request path from context, ensure it starts with '/' and break into
		// tokens (ignoring leading '/'), then locate Guid value if present:
		string? path = context?.Request?.Path;
		if (path?.StartsWith('/') ?? false)
		{
			var pathSegments = path[1..].Split('/');
			if (pathSegments.Length > _position && Guid.TryParse(pathSegments[_position], out var guid))
			{
				return Task.FromResult<Guid?>(guid);
			}
		}

		// Path not available, could not be parsed or does not contain valid Guid:
		return Task.FromResult<Guid?>(null);
	}
}
