using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization;
using AuthPolicyPOC.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class ApiAuthorizationHandlerTests
{
	#region Fields and constructor
	private readonly CaptureLogger<ApiAuthorizationHandler> _logger = new();
	private readonly ApiAuthorizationHandler _sut;
	public ApiAuthorizationHandlerTests() => _sut = new(_logger);
	#endregion

	/// <summary>
	/// Validate that if there are no requirements in context, nothing happens
	/// </summary>
	[Fact]
	public async Task If_NoRequirements_NothingHappens()
	{
		// Create context with no requirements, and strict Mock<HttpContext> resource:
		var context = new AuthorizationHandlerContext(
			requirements: Array.Empty<IAuthorizationRequirement>(),
			user: new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>())),
			resource: new Mock<HttpContext>(MockBehavior.Strict));

		// Run HandleAsync, ensuring that resource is never accessed (any attempt to access
		// Mock<HttpContext> will raise exception due to no corresponding setup):
		Assert.Null(await Record.ExceptionAsync(() => _sut.HandleAsync(context)));
	}

	/// <summary>
	/// Validate that if context has already failed, nothing happens
	/// </summary>
	[Fact]
	public async Task If_ContextHasFailed_NothingHappens()
	{
		// Create context with requirements and strict Mock<HttpContext> resource:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>())),
			resource: new Mock<HttpContext>(MockBehavior.Strict));

		// Manually fail context then run HandleAsync, ensuring that resource is never accessed
		// (any attempt to access Mock<HttpContext> will raise exception):
		context.Fail();
		Assert.Null(await Record.ExceptionAsync(() => _sut.HandleAsync(context)));
	}

	/// <summary>
	/// Validate that if there is no resource in context, request fails
	/// </summary>
	[Fact]
	public async Task If_Null_Resource_ContextFails()
	{
		// Create context with requirements and no resource:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>())),
			resource: null);

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("Failed to get HttpContext from resource (null)"));
	}

	/// <summary>
	/// Validate that if resource is not HttpContext, request fails
	/// </summary>
	[Fact]
	public async Task If_NonHttp_Resource_ContextFails()
	{
		// Create context with requirements and Guid resource:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>())),
			resource: Guid.NewGuid());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("Failed to get HttpContext from resource System.Guid"));
	}

	/// <summary>
	/// Validate that if user has no claims, request fails
	/// </summary>
	[Theory]
	[InlineData(0)] // Null user
	[InlineData(1)] // Empty ClaimsPrincipal
	[InlineData(2)] // ClaimsPrincipal with empty claims
	public async Task If_NoUserClaims_ContextFails(int testCaseType)
	{
		// Create context with requirements and HttpContext resource, but invalid user:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: testCaseType switch { 0 => null!, 1 => new ClaimsPrincipal(), _ => new ClaimsPrincipal(new ClaimsIdentity(Array.Empty<Claim>())) },
			resource: new DefaultHttpContext());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("No claims were found for the user."));
	}

	/// <summary>
	/// Validate that if user has claims but specifically no NameIdentifier claim, request fails
	/// </summary>
	[Fact]
	public async Task If_NoUserIDClaim_ContextFails()
	{
		// Create context with requirements and HttpContext resource, but missing claim:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new("RandomType", "RandomValue") })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("No user name claim was found."));
	}

	/// <summary>
	/// Validate that if user NameIdentifier claim is not a Guid, request fails
	/// </summary>
	[Fact]
	public async Task If_UserIDClaim_IsNonGuid_ContextFails()
	{
		// Create context with requirements and HttpContext resource, but invalid claim:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new(ClaimTypes.NameIdentifier, "NonGuidValue") })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("No user name claim was found."));
	}

	/// <summary>
	/// Validate that if an unrecognized requirement type is encountered, request fails and error is logged
	/// </summary>
	[Fact]
	public async Task If_UnrecognizedRequirement_ContextFails()
	{
		// Create context with Mocked requirement and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object },
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("Unhandled requirement type:"));
	}

	/// <summary>
	/// Validate that if NotAuthorizedRequirement is included in requirements, request fails
	/// </summary>
	[Fact]
	public async Task If_NotAuthorizedRequirement_ContextFails()
	{
		// Create context with Mocked requirement and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: new List<IAuthorizationRequirement>() { new NotAuthorizedRequirement() },
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed, run handler and ensure it failed:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);

		// Ensure nothing was logged (NotAuthorizedRequirement should fail silently):
		Assert.Empty(_logger.CapturedLines);
	}
}
