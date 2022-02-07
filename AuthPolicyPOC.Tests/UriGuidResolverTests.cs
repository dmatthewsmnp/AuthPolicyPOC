using System;
using System.Text;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class UriGuidResolverTests
{
	/// <summary>
	/// Validate that UriGuidResolver constructor will throw if it does not receive a valid Uri position
	/// </summary>
	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("NotAnInteger")]
	[InlineData("-1")]
	public void Constructor_Throws_If_InvalidPosition(string? position)
	{
		var ex = Record.Exception(() => _ = new UriGuidResolver(position!));
		Assert.True(ex is ArgumentOutOfRangeException aore && aore.ParamName == "position",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentOutOfRangeException)?.ParamName})");
	}

	/// <summary>
	/// Validate that given a null HttpContext, ResolveResource returns null without error
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesNullContext()
	{
		var sut = new UriGuidResolver("0");
		Assert.Null(await sut.ResolveResource(null));
	}

	/// <summary>
	/// Validate that given a path with fewer than "position" tokens, resolver gracefully returns null
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesShortUri()
	{
		var sut = new UriGuidResolver("3");
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext() { Request = { Path = "/short" } }));
	}

	/// <summary>
	/// Validate that resolver gracefully handles non-Guid in expected position
	/// </summary>
	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	public async Task ResolveResource_HandlesNonGuid(int position)
	{
		// Construct path with set number of string values (this will result in tests where expected
		// value is in various positions relative to start and end of path):
		var sut = new UriGuidResolver(position.ToString());
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext() { Request = { Path = "/0/1/2" } }));
	}

	/// <summary>
	/// Validate that resolver finds and returns Guid from expected position in path
	/// </summary>
	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(3)]
	public async Task ResolveResource_ResolvesValidGuid(int position)
	{
		// Construct path with "position" number of folders:
		var path = new StringBuilder("/");
		for (int i = 0; i < position; i++)
		{
			path.Append("prefix/");
		}

		// Add resource Guid to path:
		var resourceGuid = Guid.NewGuid();
		path.Append(resourceGuid.ToString());

		// Conditionally add suffix folders (so cases will have a mix of values where Guid is
		// and is not at the end of the Uri string):
		for (int i = position; i < 2; ++i)
		{
			path.Append("/suffix");
		}

		// Create resolver and ensure it can resolve value from constructed path:
		var sut = new UriGuidResolver(position.ToString());
		Assert.Equal(resourceGuid, await sut.ResolveResource(new DefaultHttpContext() { Request = { Path = path.ToString() } }));
	}
}
