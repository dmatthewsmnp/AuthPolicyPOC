using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class AuthorizeByGuidAttributeTests
{
	#region Object construction tests
	/// <summary>
	/// Validate that invalid resolver type causes constructor to throw
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_InvalidResolver()
	{
		var ex = Record.Exception(() => new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(int), // Invalid (value type)
			resolverArg: "1",
			guidRequirementHandler: typeof(GuidRequirementHandler))); // Valid
		Assert.True(ex is ArgumentException ae && ae.ParamName == "guidValueResolver",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that invalid resolver argument causes constructor to throw
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_InvalidResolverArg()
	{
		var ex = Record.Exception(() => new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(UriGuidResolver), // Valid
			resolverArg: string.Empty,
			guidRequirementHandler: typeof(GuidRequirementHandler))); // Valid
		Assert.True(ex is ArgumentException ae && ae.ParamName == "resolverArg",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that if guidRequirementHandler is not an IRequirementHandler, constructor throws
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_InvalidHandler()
	{
		var ex = Record.Exception(() => new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(UriGuidResolver), // Valid
			resolverArg: "1", // Valid
			guidRequirementHandler: typeof(void))); // Invalid
		Assert.True(ex is ArgumentException ae && ae.ParamName == "guidRequirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that if classRequirementHandler is an IRequirementHandler for the wrong type, constructor throws
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_HandlerWrongType()
	{
		var ex = Record.Exception(() => new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(UriGuidResolver), // Valid
			resolverArg: "1", // Valid
			guidRequirementHandler: typeof(ObjectRequirementHandler))); // Invalid (not an IRequirementHandler<Guid?>)
		Assert.True(ex is ArgumentException ae && ae.ParamName == "guidRequirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that constructor with valid arguments does not throw, and produces valid object
	/// </summary>
	[Fact]
	public void Constructor_Succeeds_If_ValidUri()
	{
		var sut = new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(UriGuidResolver), // Valid
			resolverArg: "1", // Valid
			guidRequirementHandler: typeof(GuidRequirementHandler)); // Valid
		Assert.StartsWith(AuthorizeByGuidAttribute.POLICY_PREFIX, sut!.Policy);
	}

	/// <summary>
	/// Validate that constructor with valid arguments does not throw, and produces valid object
	/// </summary>
	[Fact]
	public void Constructor_Succeeds_If_ValidJsonBody()
	{
		var sut = new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(JsonBodyGuidResolver<SampleClassToResolve>), // Valid
			resolverArg: "GuidProperty", // Valid
			guidRequirementHandler: typeof(GuidRequirementHandler)); // Valid
		Assert.StartsWith(AuthorizeByGuidAttribute.POLICY_PREFIX, sut!.Policy);
	}
	#endregion

	#region Static utility method tests
	/// <summary>
	/// Validate that passing various types of invalid policy name strings into static utility raises error
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("Invalid string")]
	[InlineData("_|__|_")]
	[InlineData("GuidRequirement_|_")]
	[InlineData("GuidRequirement_|__|_")]
	[InlineData("GuidRequirement_|__|__|_")]
	public void GetAuthorizationRequirement_Throws_If_InvalidPolicyName(string policyName)
	{
		var ex = Record.Exception(() => AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: policyName));
		Assert.True(ex is InvalidOperationException && ex.Message == "Invalid policy string");
	}

	/// <summary>
	/// Validate that syntactically-correct string with value types raises error
	/// </summary>
	[Fact]
	public void GetAuthorizationRequirement_Throws_If_ValueTypes()
	{
		var ex = Record.Exception(() => AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: "GuidRequirement_|_System.Int32_|_System.Int32_|_ResolverArg"));
		Assert.True(ex is InvalidOperationException);
	}

	/// <summary>
	/// Validate that a syntactically-valid string with invalid handler type raises error
	/// </summary>
	[Theory]
	[InlineData(typeof(SampleClassToResolve))] // Not an IRequirementHandler at all
	[InlineData(typeof(ObjectRequirementHandler))] // IRequirementHandler for wrong type
	public void GetAuthorizationRequirement_Throws_If_InvalidHandler(Type T)
	{
		var ex = Record.Exception(() => AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: $"{AuthorizeByGuidAttribute.POLICY_PREFIX}{typeof(UriGuidResolver).AssemblyQualifiedName}_|_{T.AssemblyQualifiedName}_|_1"));
		Assert.True(ex is ArgumentNullException ane && ane.ParamName == "requirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentNullException)?.ParamName})");
	}

	/// <summary>
	/// Validate that a valid UriGuidResolver string with invalid parameter raises error
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("-1")]
	[InlineData("NotAnInt")]
	public void GetAuthorizationRequirement_Throws_If_InvalidUriResolverArg(string resolverArg)
	{
		var ex = Record.Exception(() => AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: $"{AuthorizeByGuidAttribute.POLICY_PREFIX}{typeof(UriGuidResolver).AssemblyQualifiedName}_|_{typeof(GuidRequirementHandler).AssemblyQualifiedName}_|_{resolverArg}"));
		Assert.True(ex is ArgumentOutOfRangeException aore && aore.ParamName == "position",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentOutOfRangeException)?.ParamName})");
	}

	/// <summary>
	/// Validate that a valid JsonBodyGuidResolver string with invalid parameter raises error
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("NotAValidProperty")]
	[InlineData("IntProperty")]
	public void GetAuthorizationRequirement_Throws_If_InvalidJsonBodyResolverArg(string resolverArg)
	{
		var ex = Record.Exception(() => AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: $"{AuthorizeByGuidAttribute.POLICY_PREFIX}{typeof(JsonBodyGuidResolver<SampleClassToResolve>).AssemblyQualifiedName}_|_{typeof(GuidRequirementHandler).AssemblyQualifiedName}_|_{resolverArg}"));
		Assert.True(ex is ArgumentException ae && ae.ParamName == "fieldname",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that an AuthorizationRequirement can be created correctly from a valid Attribute with Uri resolver
	/// </summary>
	[Fact]
	public void GetAuthorizationRequirement_CreatesCorrectRequirement_Uri()
	{
		// Create valid attribute object:
		var attribute = new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(UriGuidResolver), // Valid
			resolverArg: "1", // Valid
			guidRequirementHandler: typeof(GuidRequirementHandler)); // Valid

		// Extract authorization requirement from attribute's Policy string:
		var authReq = AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: attribute.Policy!);

		// Validate that requirement object was created with correct object types:
		Assert.NotNull(authReq);
		Assert.Equal(typeof(GuidRequirementHandler), authReq.RequirementHandlerType);
		Assert.True(authReq.ResourceResolver is UriGuidResolver ugr && ugr.Position == 1,
			$"ResourceResolver is wrong type ({authReq.ResourceResolver.GetType()}) or has wrong Uri position ({(authReq.ResourceResolver as UriGuidResolver)?.Position})");
	}

	/// <summary>
	/// Validate that an AuthorizationRequirement can be created correctly from a valid Attribute with JsonBody resolver
	/// </summary>
	[Fact]
	public void GetAuthorizationRequirement_CreatesCorrectRequirement_JsonBody()
	{
		// Create valid attribute object:
		var attribute = new AuthorizeByGuidAttribute(
			guidValueResolver: typeof(JsonBodyGuidResolver<SampleClassToResolve>), // Valid
			resolverArg: "GuidProperty", // Valid
			guidRequirementHandler: typeof(GuidRequirementHandler)); // Valid

		// Extract authorization requirement from attribute's Policy string:
		var authReq = AuthorizeByGuidAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: attribute.Policy!);

		// Validate that requirement object was created with correct object types:
		Assert.NotNull(authReq);
		Assert.Equal(typeof(GuidRequirementHandler), authReq.RequirementHandlerType);
		Assert.True(authReq.ResourceResolver is JsonBodyGuidResolver<SampleClassToResolve> jbg && jbg.Property == "GuidProperty",
			$"ResourceResolver is wrong type ({authReq.ResourceResolver.GetType()}) or has wrong property ({(authReq.ResourceResolver as JsonBodyGuidResolver<SampleClassToResolve>)?.Property})");
	}
	#endregion

	#region Private mock handler classes
	/// <summary>
	/// Object type handler (should not be valid for use with AuthorizeByGuidAttribute)
	/// </summary>
	private class ObjectRequirementHandler : IRequirementHandler<object?>
	{
		public Task<bool> CheckRequirement(object? resource, List<Guid>? clientClaims, Guid? userClaim)
		{
			return Task.FromResult(true);
		}
	}

	/// <summary>
	/// Value type handler (should be valid for use with AuthorizeByGuidAttribute)
	/// </summary>
	private class GuidRequirementHandler : IRequirementHandler<Guid?>
	{
		public Task<bool> CheckRequirement(Guid? resource, List<Guid>? clientClaims, Guid? userClaim)
		{
			return Task.FromResult(true);
		}
	}

	/// <summary>
	/// Placeholder class for use as resolution target
	/// </summary>
	[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Used by tests")]
	private sealed class SampleClassToResolve
	{
		public int IntProperty { get; set; }

		public Guid? GuidProperty { get; set; }
	}
	#endregion
}
