using System;
using System.Net;
using System.Threading.Tasks;
using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class MvcSignedUrlAttributeIntegrationTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    [Fact]
    public async Task ActionLevelAttribute_ReturnsOk_ForValidSignedUrl()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/mvc/action-protected?file=report", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("action-ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ControllerLevelAttribute_ReturnsOk_ForValidSignedUrl()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/mvc/controller-protected", TimeSpan.FromMinutes(5), Key);

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("controller-ok", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Attribute_ReturnsUnauthorized_WhenSignatureIsMissing()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();

        var response = await client.GetAsync("/mvc/action-protected?file=report");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Attribute_ReturnsUnauthorized_WhenSignedUrlIsExpired()
    {
        var timeProvider = new FakeTimeProvider(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));
        await using var app = await CreateAppAsync(timeProvider);
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/mvc/action-protected?file=report", TimeSpan.FromMinutes(5), Key, timeProvider);

        timeProvider.Advance(TimeSpan.FromMinutes(10));

        var response = await client.GetAsync(signedUrl);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Attribute_ReturnsOk_WhenSignedUrlQueryIsReordered()
    {
        await using var app = await CreateAppAsync();
        using var client = app.GetTestClient();
        var signedUrl = TimedUrlSigner.Sign("/mvc/action-protected?b=2&a=1", TimeSpan.FromMinutes(5), Key);
        var reorderedSignedUrl = ReorderQuery(signedUrl, "a", "b", "exp", "sig");

        var response = await client.GetAsync(reorderedSignedUrl);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("action-ok", await response.Content.ReadAsStringAsync());
    }

    private static async Task<WebApplication> CreateAppAsync(TimeProvider? timeProvider = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services
            .AddControllers()
            .AddApplicationPart(typeof(MvcSignedUrlAttributeIntegrationTest).Assembly);
        builder.Services.AddSignedUrlValidation(options =>
        {
            options.UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider ?? TimeProvider.System);
        });

        var app = builder.Build();
        app.MapControllers();

        await app.StartAsync();
        return app;
    }

    private static string ReorderQuery(string url, params string[] orderedParameterNames)
    {
        var queryIndex = url.IndexOf('?');
        if (queryIndex < 0)
        {
            return url;
        }

        var prefix = url[..queryIndex];
        var segments = url[(queryIndex + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries);
        var reorderedSegments = new string[segments.Length];
        var index = 0;

        foreach (var parameterName in orderedParameterNames)
        {
            foreach (var segment in segments)
            {
                if (segment.StartsWith(parameterName + "=", StringComparison.Ordinal))
                {
                    reorderedSegments[index++] = segment;
                }
            }
        }

        foreach (var segment in segments)
        {
            var alreadyAdded = false;
            for (var i = 0; i < index; i++)
            {
                if (string.Equals(reorderedSegments[i], segment, StringComparison.Ordinal))
                {
                    alreadyAdded = true;
                    break;
                }
            }

            if (!alreadyAdded)
            {
                reorderedSegments[index++] = segment;
            }
        }

        return $"{prefix}?{string.Join("&", reorderedSegments, 0, index)}";
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private DateTimeOffset currentUtcNow;

        public FakeTimeProvider(DateTimeOffset utcNow)
        {
            currentUtcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => currentUtcNow;

        public void Advance(TimeSpan by) => currentUtcNow = currentUtcNow.Add(by);
    }
}



