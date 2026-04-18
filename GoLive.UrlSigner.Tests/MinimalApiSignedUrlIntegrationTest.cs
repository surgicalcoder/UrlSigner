using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using GoLive.UrlSigner.MinimalApis;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.TestHost;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class MinimalApiSignedUrlIntegrationTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    private static readonly byte[] JwtKey = Encoding.UTF8.GetBytes("0123456789ABCDEF0123456789ABCDEF");

    [Fact]
    public async Task PlainRoute_Authenticates_WhenUrlSignatureIsValid()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/minimal/plain", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("plain-ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task PlainRoute_ReturnsUnauthorized_WhenSignatureIsMissing()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.GetAsync("/minimal/plain");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenRoute_PopulatesUser_WhenCustomPrincipalResolverIsConfigured()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("user-123"));
        var signedUrl = TimedUrlSigner.Sign($"/minimal/secure?token={token}", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("user-123", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task TokenRoute_Authenticates_WhenJwtValidationParametersAreConfigured()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var jwt = CreateJwt();
        var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt));
        var signedUrl = TimedUrlSigner.Sign($"/minimal/jwt?token={token}", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("jwt-user", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task TokenRoute_ReturnsUnauthorized_WhenTokenIsMissing()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/minimal/secure", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<WebApplication> CreateAppAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();

        var app = builder.Build();

        app.MapGet("/minimal/plain", () => Results.Text("plain-ok"))
            .RequireSignedUrl(Key);

        app.MapGet("/minimal/secure", (HttpContext context) =>
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
            return Results.Text(userId);
        }).RequireSignedUrlToken(Key, options =>
        {
            options.GetPrincipal = static (tokenBytes, _) =>
            {
                var userId = Encoding.UTF8.GetString(tokenBytes.Span);
                var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, userId) }, "SignedUrlMinimalApi");
                return ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(identity));
            };
        });

        app.MapGet("/minimal/jwt", (HttpContext context) =>
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
            return Results.Text(userId);
        }).RequireSignedUrlToken(Key, options =>
        {
            options.TokenValidationParameters = CreateTokenValidationParameters();
        });

        await app.StartAsync();
        return app;
    }

    private static string CreateJwt()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "jwt-user") }),
            Issuer = "UrlSigner.Tests",
            Audience = "UrlSigner.Tests",
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(JwtKey), SecurityAlgorithms.HmacSha256)
        };

        return tokenHandler.WriteToken(tokenHandler.CreateToken(descriptor));
    }

    private static TokenValidationParameters CreateTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "UrlSigner.Tests",
            ValidateAudience = true,
            ValidAudience = "UrlSigner.Tests",
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(JwtKey),
            ValidateLifetime = false
        };
    }
}

