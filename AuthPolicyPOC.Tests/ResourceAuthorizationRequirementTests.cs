using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthPolicyPOC.Authorization.Requirements;
using AuthPolicyPOC.Authorization.Resolvers;
using Microsoft.AspNetCore.Http;
using Moq;
using Xunit;

namespace AuthPolicyPOC.Tests;

[Trait("Category", "Unit")]
public class ResourceAuthorizationRequirementTests
{
	private readonly Mock<IResourceResolver<Guid>> _mockGuidResolver = new(MockBehavior.Strict);
	private readonly Mock<IRequirementHandler<Guid>> _mockGuidHandler = new(MockBehavior.Strict);

	/// <summary>
	/// Validate that if one or both arguments are missing, constructor will throw
	/// </summary>
	[Theory]
	[InlineData(0)] // Both types null
	[InlineData(1)] // Resolver null
	[InlineData(2)] // Requirement handler null
	public void Constructor_Throws_If_TypesNull(int testCaseType)
	{
		var ex = Record.Exception(() => _ = new ResourceAuthorizationRequirement<Guid>(
			resourceResolver: testCaseType == 2 ? _mockGuidResolver.Object : null,
			requirementHandler: testCaseType == 1 ? _mockGuidHandler.Object : null));
		Assert.True(ex is ArgumentNullException ane && ane.ParamName == (testCaseType == 2 ? "requirementHandler" : "resourceResolver"),
			$"Invalid exception type ({ex.GetType()}) or parameter name ({(ex as ArgumentNullException)?.ParamName})");
	}

	/// <summary>
	/// Validate that CheckRequirement method will call resolver and handler methods as expected
	/// </summary>
	[Fact]
	public async Task CheckRequirement_WorksAsExpected()
	{
		// Set up resource value and mock resolver:
		var resourceGuid = Guid.NewGuid();
		_mockGuidResolver.Setup(x => x.ResolveResource(It.IsAny<HttpContext?>()))
			.Returns(Task.FromResult(resourceGuid))
			.Verifiable();

		// Set up claims values and handler mock:
		var userGuid = Guid.NewGuid();
		var clientGuid = Guid.NewGuid();
		_mockGuidHandler.Setup(x => x.CheckRequirement(resourceGuid, It.Is<List<Guid>?>(list => list != null && list.Single() == clientGuid), userGuid))
			.Returns(Task.FromResult(true))
			.Verifiable();

		// Create requirement object with mocks, and ensure it returns success:
		var sut = new ResourceAuthorizationRequirement<Guid>(
			resourceResolver: _mockGuidResolver.Object,
			requirementHandler: _mockGuidHandler.Object);
		Assert.True(await sut.CheckRequirement(new DefaultHttpContext(), new List<Guid>() { clientGuid }, userGuid));

		// Verify that both mock methods were called:
		_mockGuidResolver.Verify();
		_mockGuidHandler.Verify();
	}
}
