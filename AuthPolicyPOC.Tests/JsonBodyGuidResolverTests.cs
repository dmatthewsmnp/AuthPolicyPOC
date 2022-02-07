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
public class JsonBodyGuidResolverTests
{
	#region Constructor tests
	/// <summary>
	/// Validate that constructor throws error if null property name provided
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_NullResolverArg()
	{
		var ex = Record.Exception(() => _ = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: null!));
		Assert.True(ex is ArgumentNullException ae && ae.ParamName == "fieldname",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentNullException)?.ParamName})");
	}

	/// <summary>
	/// Validate that constructor throws error if argument does not match a Guid property
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("NotAValidProperty")]
	[InlineData("IntProperty")]
	public void Constructor_Throws_If_InvalidResolverArg(string resolverArg)
	{
		var ex = Record.Exception(() => _ = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: resolverArg));
		Assert.True(ex is ArgumentException ae && ae.ParamName == "fieldname",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}
	#endregion

	#region ResolveResource tests
	/// <summary>
	/// Ensure ResolveResource gracefully handles null HttpContext
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesNullContext()
	{
		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
		Assert.Null(await sut.ResolveResource(null));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with no request content
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesDefaultContext()
	{
		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles HttpContext with wrong ContentType
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesWrongContentType()
	{
		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
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

		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
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

		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}

	/// <summary>
	/// Ensure ResolveResource gracefully handles a deserialized object with a null Guid property
	/// </summary>
	[Fact]
	public async Task ResolveResource_HandlesNullValue()
	{
		// Create valid request body, but leaving GuidProperty null:
		using var requeststream = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new SampleClassToResolve { IntProperty = 5 })));

		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
		Assert.Null(await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}

	/// <summary>
	/// Ensure ResolveResource successfully resolves a valid Guid property from deserialized object
	/// </summary>
	[Fact]
	public async Task ResolveResource_ResolvesValidGuid()
	{
		// Create valid request body, with valid GuidProperty:
		var request = new SampleClassToResolve { GuidProperty = Guid.NewGuid() };
		using var requeststream = new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request)));

		var sut = new JsonBodyGuidResolver<SampleClassToResolve>(fieldname: "GuidProperty");
		Assert.Equal(request.GuidProperty, await sut.ResolveResource(new DefaultHttpContext()
		{
			Request = {
				ContentType = "application/json",
				Body = requeststream
			}
		}));
	}
	#endregion

	#region Private class definitions
	/// <summary>
	/// Placeholder class for use as resolution target
	/// </summary>
	private sealed class SampleClassToResolve
	{
		public int IntProperty { get; set; }

		public Guid? GuidProperty { get; set; }
	}
	#endregion
}
