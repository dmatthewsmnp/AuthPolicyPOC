using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
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
	private readonly Mock<ResourceAuthorizationRequirement> _mockApproveRequirement = new();
	public ApiAuthorizationHandlerTests()
	{
		_sut = new(_logger);

		// Set up approval requirement to always return success:
		_mockApproveRequirement.Setup(x => x.CheckRequirement(It.IsAny<HttpContext?>(), It.IsAny<List<Guid>?>(), It.IsAny<Guid?>()))
			.Returns(Task.FromResult(true))
			.Verifiable();
	}
	#endregion

	#region Context and claims tests
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

		// Ensure context has not failed before test, but has afterward:
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

		// Ensure context has not failed before test, but has afterward:
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

		// Ensure context has not failed before test, but has afterward:
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

		// Ensure context has not failed before test, but has afterward:
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

		// Ensure context has not failed before test, but has afterward:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("No user name claim was found."));
	}
	#endregion

	#region Requirements tests
	/// <summary>
	/// Validate that if an unrecognized requirement type is encountered, request fails and error is logged
	/// </summary>
	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task If_UnrecognizedRequirement_ContextFails(bool generateNoise)
	{
		// Create requirements collection with mocked requirement (will raise exception if actually called),
		// start with auto-approve requirement at start of queue if requested:
		var requirements = new Queue<IAuthorizationRequirement>();
		if (generateNoise)
		{
			requirements.Enqueue(_mockApproveRequirement.Object);
		}
		requirements.Enqueue(new Mock<IAuthorizationRequirement>(MockBehavior.Strict).Object);

		// Create context with requirements collection and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: requirements,
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed before test, but has afterward:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		Assert.Contains(_logger.CapturedLines, line => line.Contains("Unhandled requirement type:"));

		// If auto-approve requirement was included, ensure it was checked (should have
		// been, since it was first in queue):
		if (generateNoise)
		{
			_mockApproveRequirement.Verify();
		}
	}

	/// <summary>
	/// Validate that if NotAuthorizedRequirement is included in requirements, request fails
	/// </summary>
	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task If_NotAuthorizedRequirement_ContextFails(bool generateNoise)
	{
		// Create requirements collection with NotAuthorizedRequirement, starting with auto-approve requirement if requested:
		var requirements = new Queue<IAuthorizationRequirement>();
		if (generateNoise)
		{
			requirements.Enqueue(_mockApproveRequirement.Object);
		}
		requirements.Enqueue(new NotAuthorizedRequirement());

		// Create context with requirements collection and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: requirements,
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()) })),
			resource: new DefaultHttpContext());

		// Ensure context has not failed before test, but has afterward:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);

		// Ensure nothing was logged (NotAuthorizedRequirement should fail silently):
		Assert.Empty(_logger.CapturedLines);

		// If auto-approve requirement was included, ensure it was checked (should have
		// been, since it was first in queue):
		if (generateNoise)
		{
			_mockApproveRequirement.Verify();
		}
	}

	/// <summary>
	/// Validate that if a ResourceAuthorizationRequirement fails, request fails
	/// </summary>
	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task If_RequirementFails_ContextFails(bool generateNoise)
	{
		// Set up context variables:
		var httpContext = new DefaultHttpContext();
		var userGuid = Guid.NewGuid();
		var clientGuid = Guid.NewGuid();

		// Create requirements collection, starting with auto-approve requirement if requested:
		var requirements = new Queue<IAuthorizationRequirement>();
		if (generateNoise)
		{
			requirements.Enqueue(_mockApproveRequirement.Object);
		}

		// Create mock version of ResourceAuthorizationRequirement returning false result and add to collection:
		var mockFailRequirement = new Mock<ResourceAuthorizationRequirement>();
		mockFailRequirement.Setup(x => x.CheckRequirement(
				httpContext,
				It.Is<List<Guid>?>(list => list != null && list.Single() == clientGuid),
				userGuid)
			)
			.Returns(Task.FromResult(false))
			.Verifiable();
		requirements.Enqueue(mockFailRequirement.Object);

		// Create context with requirements collection and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: requirements,
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
			{
				new(ClaimTypes.NameIdentifier, userGuid.ToString()),
				new("clientAccess", clientGuid.ToString())
			})),
			resource: httpContext);

		// Ensure context has not failed before test, but has afterward:
		Assert.False(context.HasFailed);
		await _sut.HandleAsync(context);
		Assert.True(context.HasFailed);
		mockFailRequirement.Verify();

		// Ensure nothing was logged (routine decline should fail silently):
		Assert.Empty(_logger.CapturedLines);

		// If auto-approve requirement was included, ensure it was checked (should have
		// been, since it was first in queue):
		if (generateNoise)
		{
			_mockApproveRequirement.Verify();
		}
	}

	/// <summary>
	/// Validate that if all ResourceAuthorizationRequirements pass, request passes
	/// </summary>
	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task If_RequirementsSucceed_ContextSucceeds(bool generateNoise)
	{
		// Set up context variables:
		var httpContext = new DefaultHttpContext();
		var userGuid = Guid.NewGuid();
		var clientGuid = Guid.NewGuid();

		// Create requirements collection, starting with auto-approve requirement:
		var requirements = new Queue<IAuthorizationRequirement>();
		requirements.Enqueue(_mockApproveRequirement.Object);
		var mockReqList = new List<Mock<ResourceAuthorizationRequirement>>();
		if (generateNoise)
		{
			// Generate a bunch of mocked authorization requirements, all returning success:
			for (int i = 0; i < 10; ++i)
			{
				var mockRequirement = new Mock<ResourceAuthorizationRequirement>();
				mockRequirement.Setup(x => x.CheckRequirement(httpContext, It.Is<List<Guid>?>(list => list != null && list.Single() == clientGuid), userGuid)).Returns(Task.FromResult(true)).Verifiable();
				mockReqList.Add(mockRequirement);
				requirements.Enqueue(mockRequirement.Object);
			}
		}

		// Create context with requirements collection and valid user/resource:
		var context = new AuthorizationHandlerContext(
			requirements: requirements,
			user: new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
			{
				new(ClaimTypes.NameIdentifier, userGuid.ToString()),
				new("clientAccess", clientGuid.ToString())
			})),
			resource: httpContext);

		// Ensure context has not succeeded before test, but has afterward:
		Assert.False(context.HasSucceeded);
		await _sut.HandleAsync(context);
		Assert.True(context.HasSucceeded);

		// Ensure all pending requirements were removed and that all mock requirements were called:
		Assert.Empty(context.PendingRequirements);
		_mockApproveRequirement.Verify();
		foreach (var mockRequirement in mockReqList)
		{
			mockRequirement.Verify();
		}
	}
	#endregion
}
