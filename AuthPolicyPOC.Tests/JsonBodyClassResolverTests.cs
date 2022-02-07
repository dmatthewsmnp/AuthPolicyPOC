using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class JsonBodyClassResolverTests
{
	/// <summary>
	/// Ensure ResolveResource gracefully handles null HttpContext
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesNullContext()
	{
		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Null(await sut.ResolveResource(null));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with no request content
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesDefaultContext()
	{
		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with wrong ContentType
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesWrongContentType()
	{
		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = { ContentType = "application/xml" }
		}));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with invalid Json content
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesNonJsonContent()
	{
		using var requeststream = new MemoryStream(Encoding.UTF8.GetBytes("NonJsonContent"));

		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with wrong kind of Json object content
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesWrongJsonContent()
	{
		using var requeststream = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { GuidValue = Guid.NewGuid() })));

		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Equal(new SampleClassToResolve(), await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}

	/// <summary>
	/// Ensure ResolveResource successfully resolves a valid object from deserialized object
	/// </summary>
	[Fact]
	public async Task ResolveResource_ResolvesValidGuid()
	{
		// Create valid request body, with valid GuidProperty:
		var request = new SampleClassToResolve { IntProperty = 77, GuidProperty = Guid.NewGuid() };
		using var requeststream = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request)));

		var sut = new JsonBodyClassResolver(typeof(SampleClassToResolve));
		Assert.Equal(request, await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}

	#region Private class definitions
	/// <summary>
	/// Simple class for use as resolution target
	/// </summary>
	[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1067:Override Object.Equals(object) when implementing IEquatable<T>", Justification = "This is a test class only")]
	private sealed class SampleClassToResolve : IEquatable<SampleClassToResolve>
	{
		public int IntProperty { get; set; }

		public Guid? GuidProperty { get; set; }

		public bool Equals(SampleClassToResolve? other)
		{
			return IntProperty == other?.IntProperty && GuidProperty == other?.GuidProperty;
		}
	}
	#endregion
}
