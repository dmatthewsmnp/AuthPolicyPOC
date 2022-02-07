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
public class AuthorizeByClassAttributeTests
{
	#region Object construction tests
	/// <summary>
	/// Validate that if non-reference-type is passed as class to resolve, constructor throws
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_ClassIsValueType()
	{
		var ex = Record.Exception(() => new AuthorizeByClassAttribute(
			classToResolve: typeof(int), // Invalid (value type)
			classRequirementHandler: typeof(ObjectRequirementHandler))); // Valid
		Assert.True(ex is ArgumentException ae && ae.ParamName == "classToResolve",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that if classRequirementHandler is not an IRequirementHandler, constructor throws
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_InvalidHandler()
	{
		var ex = Record.Exception(() => new AuthorizeByClassAttribute(
			classToResolve: typeof(SampleClassToResolve), // Valid (reference type)
			classRequirementHandler: typeof(void))); // Invalid
		Assert.True(ex is ArgumentException ae && ae.ParamName == "classRequirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that if classRequirementHandler is an IRequirementHandler for the wrong type, constructor throws
	/// </summary>
	[Fact]
	public void Constructor_Throws_If_HandlerWrongType()
	{
		var ex = Record.Exception(() => new AuthorizeByClassAttribute(
			classToResolve: typeof(SampleClassToResolve), // Valid (reference type)
			classRequirementHandler: typeof(GuidRequirementHandler))); // Invalid (not an IRequirementHandler<object?>)
		Assert.True(ex is ArgumentException ae && ae.ParamName == "classRequirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentException)?.ParamName})");
	}

	/// <summary>
	/// Validate that constructor with valid arguments does not throw, and produces valid object
	/// </summary>
	[Fact]
	public void Constructor_Succeeds_If_Valid()
	{
		var sut = new AuthorizeByClassAttribute(
			classToResolve: typeof(SampleClassToResolve),
			classRequirementHandler: typeof(ObjectRequirementHandler));
		Assert.StartsWith(AuthorizeByClassAttribute.POLICY_PREFIX, sut!.Policy);
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
	[InlineData("ClassRequirement_|_")]
	[InlineData("ClassRequirement_|__|_")]
	public void GetAuthorizationRequirement_Throws_If_InvalidPolicyName(string policyName)
	{
		var ex = Record.Exception(() => AuthorizeByClassAttribute.GetAuthorizationRequirement(
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
		var ex = Record.Exception(() => AuthorizeByClassAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: "ClassRequirement_|_System.Int32_|_System.Int32"));
		Assert.True(ex is InvalidOperationException);
	}

	/// <summary>
	/// Validate that a syntactically-valid string with invalid handler type raises error
	/// </summary>
	[Theory]
	[InlineData(typeof(SampleClassToResolve))] // Not an IRequirementHandler at all
	[InlineData(typeof(GuidRequirementHandler))] // IRequirementHandler for wrong type
	public void GetAuthorizationRequirement_Throws_If_InvalidHandler(Type T)
	{
		var ex = Record.Exception(() => AuthorizeByClassAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: $"{AuthorizeByClassAttribute.POLICY_PREFIX}{typeof(SampleClassToResolve).AssemblyQualifiedName}_|_{T.AssemblyQualifiedName}"));
		Assert.True(ex is ArgumentNullException ane && ane.ParamName == "requirementHandler",
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentNullException)?.ParamName})");
	}

	/// <summary>
	/// Validate that an AuthorizationRequirement can be created correctly from a valid Attribute
	/// </summary>
	[Fact]
	public void GetAuthorizationRequirement_CreatesCorrectRequirement()
	{
		// Create valid attribute object:
		var attribute = new AuthorizeByClassAttribute(
			classToResolve: typeof(SampleClassToResolve),
			classRequirementHandler: typeof(ObjectRequirementHandler));

		// Extract authorization requirement from attribute's Policy string:
		var authReq = AuthorizeByClassAttribute.GetAuthorizationRequirement(
			isp: new ServiceCollection().BuildServiceProvider(),
			policyName: attribute.Policy!);

		// Validate that requirement object was created with correct object types:
		Assert.NotNull(authReq);
		Assert.Equal(typeof(ObjectRequirementHandler), authReq.RequirementHandlerType);
		Assert.True(authReq.ResourceResolver is JsonBodyClassResolver jbcr && jbcr.ClassType == typeof(SampleClassToResolve),
			$"ResourceResolver is wrong type ({authReq.ResourceResolver.GetType()}) or resolving wrong type ({(authReq.ResourceResolver as JsonBodyClassResolver)?.ClassType})");
	}
	#endregion

	#region Private mock handler classes
	/// <summary>
	/// Value type handler (should not be valid for use with AuthorizeByClassAttribute)
	/// </summary>
	private class GuidRequirementHandler : IRequirementHandler<Guid?>
	{
		public Task<bool> CheckRequirement(Guid? resource, List<Guid>? clientClaims, Guid? userClaim)
		{
			return Task.FromResult(true);
		}
	}

	/// <summary>
	/// Object type handler (should be valid for use with AuthorizeByClassAttribute)
	/// </summary>
	private class ObjectRequirementHandler : IRequirementHandler<object?>
	{
		public Task<bool> CheckRequirement(object? resource, List<Guid>? clientClaims, Guid? userClaim)
		{
			return Task.FromResult(true);
		}
	}

	/// <summary>
	/// Placeholder class for use as resolution target
	/// </summary>
	private sealed class SampleClassToResolve
	{
	}
	#endregion
}
