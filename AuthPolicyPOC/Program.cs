using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
		.AddJwtBearer(
			options =>
			{
				options.TokenValidationParameters = new TokenValidationParameters
				{
					// Not actually interested in contents of JWT for this POC; just generated value from http://jwtbuilder.jamiekurtz.com/
					ValidateIssuer = false,
					ValidateIssuerSigningKey = false,
					ValidateAudience = false,
					ValidateLifetime = false,
					RequireExpirationTime = false,
					RequireSignedTokens = false,
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("qwertyuiopasdfghjklzxcvbnm123456"))
				};
				options.Events = new JwtBearerEvents
				{
					OnAuthenticationFailed = context =>
					{
						return Task.CompletedTask;
					}

				};
			});

builder.Services.AddSingleton<IAuthorizationPolicyProvider, AuthPolicyPOC.Tests.AuthorizePolicyProvider>();
builder.Services.AddSingleton<IAuthorizationHandler, AuthPolicyPOC.Tests.AuthorizationHandler>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
{
	In = ParameterLocation.Header,
	Description = "Please insert JWT with Bearer into field",
	Name = "Authorization",
	Type = SecuritySchemeType.ApiKey,
	BearerFormat = "JWT",
	Scheme = "Bearer"
}));


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
