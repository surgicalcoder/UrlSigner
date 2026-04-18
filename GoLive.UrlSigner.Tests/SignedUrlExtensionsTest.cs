using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using GoLive.UrlSigner.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class SignedUrlExtensionsTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

    [Fact]
    public async Task AddSignedUrlAuthentication_WithDirectKey_ConfiguresSchemeWithoutTimedUrlSignerRegistration()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddAuthentication()
            .AddSignedUrlAuthentication(Key, options =>
            {
                options.GetPrincipal = static (_, _) => ValueTask.FromResult<System.Security.Claims.ClaimsPrincipal?>(new System.Security.Claims.ClaimsPrincipal());
            });

        await using var provider = services.BuildServiceProvider();
        var schemeProvider = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        var optionsMonitor = provider.GetRequiredService<IOptionsMonitor<SignedUrlAuthenticationSchemeOptions>>();

        var scheme = await schemeProvider.GetSchemeAsync(SignedUrlHandler.SchemeName);
        var options = optionsMonitor.Get(SignedUrlHandler.SchemeName);

        Assert.NotNull(scheme);
        Assert.Equal(typeof(SignedUrlHandler), scheme.HandlerType);
        Assert.NotNull(options.UrlSignerFactory);
        Assert.NotNull(options.GetPrincipal);
        Assert.Null(provider.GetService<TimedUrlSigner>());

        var signedUrl = TimedUrlSigner.Sign("/files/report?token=abc", TimeSpan.FromMinutes(5), Key);

        Assert.True(options.UrlSignerFactory!(provider).Verify(signedUrl));
    }

    [Fact]
    public void AddSignedUrlAuthentication_RejectsEmptyKey()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var builder = services.AddAuthentication();

        var ex = Assert.Throws<ArgumentException>(() => builder.AddSignedUrlAuthentication<HMACSHA512>(ReadOnlyMemory<byte>.Empty));

        Assert.Contains("Key must not be empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}


