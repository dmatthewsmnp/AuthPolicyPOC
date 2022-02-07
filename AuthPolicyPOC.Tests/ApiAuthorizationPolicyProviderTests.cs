using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization;
using AuthPolicyPOC.Authorization.Attributes;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class ApiAuthorizationPolicyProviderTests
{
	/// <summary>
	/// Validate that policy provider can rehydrate an AuthorizeByGuidAttribute into the proper ResourceAuthorizationRequirement
	/// </summary>
	/// <returns></returns>
	[Fact]
	public async Task GetPolicyAsync_Creates_AuthorizeByGuid()
	{
		// Create valid AuthorizeByGuidAttribute:
		var attribute = new AuthorizeByGuidAttribute(guidValueResolver: typeof(UriGuidResolver), resolverArg: "1", guidRequirementHandler: typeof(GuidRequirementHandler));

		// Create policy provider object and retrieve policy from attribute's Policy string:
		var sut = new ApiAuthorizationPolicyProvider(new ServiceCollection().BuildServiceProvider());
		var authPolicy = await sut.GetPolicyAsync(attribute.Policy!);
		Assert.NotNull(authPolicy);

		// Extract authorization requirement from policy (should be single value only), and ensure it is as expected:
		var authReq = authPolicy!.Requirements?.Single() as ResourceAuthorizationRequirement<Guid?>;
		Assert.NotNull(authReq);
		Assert.Equal(typeof(GuidRequirementHandler), authReq!.RequirementHandlerType);
		Assert.True(authReq.ResourceResolver is UriGuidResolver ugr && ugr.Position == 1,
			$"ResourceResolver is wrong type ({authReq.ResourceResolver.GetType()}) or has wrong Uri position ({(authReq.ResourceResolver as UriGuidResolver)?.Position})");
	}

	/// <summary>
	/// Validate that policy provider can rehydrate an AuthorizeByClassAttribute into the proper ResourceAuthorizationRequirement
	/// </summary>
	[Fact]
	public async Task GetPolicyAsync_Creates_AuthorizeByClass()
	{
		// Create valid AuthorizeByClassAttribute:
		var attribute = new AuthorizeByClassAttribute(classToResolve: typeof(SampleClassToResolve), classRequirementHandler: typeof(ObjectRequirementHandler));

		// Create policy provider object and retrieve policy from attribute's Policy string:
		var sut = new ApiAuthorizationPolicyProvider(new ServiceCollection().BuildServiceProvider());
		var authPolicy = await sut.GetPolicyAsync(attribute.Policy!);
		Assert.NotNull(authPolicy);

		// Extract authorization requirement from policy (should be single value only), and ensure it is as expected:
		var authReq = authPolicy!.Requirements?.Single() as ResourceAuthorizationRequirement<object?>;
		Assert.NotNull(authReq);
		Assert.Equal(typeof(ObjectRequirementHandler), authReq!.RequirementHandlerType);
		Assert.True(authReq.ResourceResolver is JsonBodyClassResolver jbcr && jbcr.ClassType == typeof(SampleClassToResolve),
			$"ResourceResolver is wrong type ({authReq.ResourceResolver.GetType()}) or resolving wrong type ({(authReq.ResourceResolver as JsonBodyClassResolver)?.ClassType})");
	}

	/// <summary>
	/// Validate that if policy provider receives an unrecognized or invalid string, it defaults to NotAuthorizedRequirement
	/// </summary>
	[Theory]
	[InlineData("")]
	[InlineData("NonsensePolicy")]
	public async Task GetPolicyAsync_Creates_NotAuthorized_IfInvalid(string policyName)
	{
		// Create policy provider object and retrieve policy from attribute's Policy string:
		var sut = new ApiAuthorizationPolicyProvider(new ServiceCollection().BuildServiceProvider());
		var authPolicy = await sut.GetPolicyAsync(policyName);
		Assert.NotNull(authPolicy);

		// Extract authorization requirement from policy (should be single value only), and ensure it is as expected:
		Assert.Equal(typeof(NotAuthorizedRequirement), authPolicy!.Requirements?.Single().GetType());
	}

	/// <summary>
	/// Validate that policy provider's default policy is a NotAuthorizedRequirement
	/// </summary>
	[Fact]
	public async Task GetDefaultPolicy_Is_NotAuthorized()
	{
		// Create policy provider object and retrieve default policy:
		var sut = new ApiAuthorizationPolicyProvider(new ServiceCollection().BuildServiceProvider());
		var authPolicy = await sut.GetDefaultPolicyAsync();
		Assert.NotNull(authPolicy);

		// Extract authorization requirement from policy (should be single value only), and ensure it is as expected:
		Assert.Equal(typeof(NotAuthorizedRequirement), authPolicy!.Requirements?.Single().GetType());
	}

	/// <summary>
	/// Validate that policy provider's fallback policy is a NotAuthorizedRequirement
	/// </summary>
	[Fact]
	public async Task GetFallbackPolicy_Is_NotAuthorized()
	{
		// Create policy provider object and retrieve fallback policy:
		var sut = new ApiAuthorizationPolicyProvider(new ServiceCollection().BuildServiceProvider());
		var authPolicy = await sut.GetFallbackPolicyAsync();
		Assert.NotNull(authPolicy);

		// Extract authorization requirement from policy (should be single value only), and ensure it is as expected:
		Assert.Equal(typeof(NotAuthorizedRequirement), authPolicy!.Requirements?.Single().GetType());
	}

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
	/// Simple class for use as resolution target
	/// </summary>
	private sealed class SampleClassToResolve
	{
	}
	#endregion
}
