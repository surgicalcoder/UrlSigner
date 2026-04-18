using System;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class SignedUrlAuthenticationIntegrationTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    [Fact]
    public async Task Pipeline_Authenticates_WhenSignedUrlMatchesPathBaseAndPath()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = CreateSignedUrl("/tenant-a/files/report", "user-123");

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("user-123", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Pipeline_ReturnsUnauthorized_WhenSignedUrlOmitsRequiredPathBase()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = CreateSignedUrl("/files/report", "user-123");
        var requestPath = "/tenant-a" + signedUrl;

        var response = await client.GetAsync(requestPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Pipeline_Authenticates_ForEncodedPathSegments()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = CreateSignedUrl("/tenant-a/files/report%20copy", "user-123");

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("user-123", await response.Content.ReadAsStringAsync());
    }

    private static async Task<WebApplication> CreateAppAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder(SignedUrlHandler.SchemeName)
                .RequireAuthenticatedUser()
                .Build());
        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = SignedUrlHandler.SchemeName;
                options.DefaultChallengeScheme = SignedUrlHandler.SchemeName;
            })
            .AddSignedUrlAuthentication(Key, options =>
            {
                options.GetPrincipal = static (tokenBytes, _) =>
                {
                    var tokenValue = Encoding.UTF8.GetString(tokenBytes.Span);
                    var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, tokenValue) }, SignedUrlHandler.SchemeName);
                    return ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(identity));
                };
            });

        var app = builder.Build();
        app.UsePathBase("/tenant-a");
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("/files/report", (HttpContext context) =>
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
            return Results.Text(userId);
        }).RequireAuthorization();

        app.MapGet("/files/report copy", (HttpContext context) =>
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
            return Results.Text(userId);
        }).RequireAuthorization();

        await app.StartAsync();
        return app;
    }

    private static string CreateSignedUrl(string path, string tokenValue)
    {
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(tokenValue));
        return TimedUrlSigner.Sign($"{path}?token={encodedToken}", TimeSpan.FromMinutes(5), Key);
    }
}



