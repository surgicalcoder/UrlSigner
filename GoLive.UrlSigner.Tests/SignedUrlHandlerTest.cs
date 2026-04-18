using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using GoLive.UrlSigner.Authentication;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace GoLive.UrlSigner.Tests;

public class SignedUrlHandlerTest
{
    private static readonly byte[] Key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    private static readonly byte[] JwtKey = Encoding.UTF8.GetBytes("0123456789ABCDEF0123456789ABCDEF");
    private static readonly TimeSpan TestTtl = TimeSpan.FromMinutes(5);

    [Fact]
    public async Task AuthenticateAsync_ReturnsSuccess_ForValidSignedUrl()
    {
        var timeProvider = CreateTimeProvider();
        var signedUrl = CreateSignedUrl("user-123", timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            GetPrincipal = static (tokenBytes, _) =>
            {
                var id = Encoding.UTF8.GetString(tokenBytes.Span);
                var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, id) }, SignedUrlHandler.SchemeName);
                return ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal(identity));
            }
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal("user-123", result.Principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenSigIsMissing()
    {
        var result = await AuthenticateAsync("/files/report?token=user-123&exp=1776515100", new SignedUrlAuthenticationSchemeOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("sig missing", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenExpIsMissing()
    {
        var result = await AuthenticateAsync("/files/report?token=user-123&sig=fake", new SignedUrlAuthenticationSchemeOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("exp missing", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenTokenIsMissing()
    {
        var result = await AuthenticateAsync("/files/report?exp=1776515100&sig=fake", new SignedUrlAuthenticationSchemeOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("token missing", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenTokenIsDuplicated()
    {
        var timeProvider = CreateTimeProvider();
        var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("user-123"));
        var signedUrl = TimedUrlSigner.Sign($"/files/report?token={token}", TestTtl, Key, timeProvider);
        var duplicatedTokenUrl = signedUrl.Replace($"token={token}", $"token={token}&token={token}", StringComparison.Ordinal);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            GetPrincipal = static (_, _) => ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal())
        };

        var result = await AuthenticateAsync(duplicatedTokenUrl, options);

        Assert.False(result.Succeeded);
        Assert.Equal("token must be supplied exactly once", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenSigIsDuplicated()
    {
        var result = await AuthenticateAsync("/files/report?token=user-123&exp=1776515100&sig=one&sig=two", new SignedUrlAuthenticationSchemeOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("sig must be supplied exactly once", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenExpIsDuplicated()
    {
        var result = await AuthenticateAsync("/files/report?token=user-123&exp=1776515100&exp=1776515200&sig=fake", new SignedUrlAuthenticationSchemeOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("exp must be supplied exactly once", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenSignerConfigurationIsMissing()
    {
        var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes("user-123"));
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            GetPrincipal = static (_, _) => ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal())
        };

        var result = await AuthenticateAsync($"/files/report?token={token}&exp=1776515100&sig=fake", options);

        Assert.False(result.Succeeded);
        Assert.Equal("Signed URL authentication is not configured with a TimedUrlSigner or UrlSignerFactory.", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_ForMalformedBase64UrlToken()
    {
        var timeProvider = CreateTimeProvider();
        var signedUrl = TimedUrlSigner.Sign("/files/report?token=not-base64!", TestTtl, Key, timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            GetPrincipal = static (_, _) => ValueTask.FromResult<ClaimsPrincipal?>(new ClaimsPrincipal())
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenPrincipalResolverReturnsNull()
    {
        var timeProvider = CreateTimeProvider();
        var signedUrl = CreateSignedUrl("user-123", timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            GetPrincipal = static (_, _) => ValueTask.FromResult<ClaimsPrincipal?>(null)
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.False(result.Succeeded);
        Assert.Equal("Principal resolver returned null.", result.Failure?.Message);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_WhenJwtValidationParametersAreMissing()
    {
        var timeProvider = CreateTimeProvider();
        var jwt = CreateJwt();
        var encodedJwt = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt));
        var signedUrl = TimedUrlSigner.Sign($"/files/report?token={encodedJwt}", TestTtl, Key, timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider)
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.False(result.Succeeded);
        Assert.Contains("TokenValidationParameters must be configured", result.Failure?.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuthenticateAsync_ReturnsSuccess_ForValidJwtUsingOptionsValidationParameters()
    {
        var timeProvider = CreateTimeProvider();
        var jwt = CreateJwt();
        var encodedJwt = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt));
        var signedUrl = TimedUrlSigner.Sign($"/files/report?token={encodedJwt}", TestTtl, Key, timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            TokenValidationParameters = CreateTokenValidationParameters()
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.True(result.Succeeded);
        Assert.Equal("jwt-user", result.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task AuthenticateAsync_ReturnsSuccess_ForValidJwtUsingDiValidationParameters()
    {
        var timeProvider = CreateTimeProvider();
        var jwt = CreateJwt();
        var encodedJwt = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt));
        var signedUrl = TimedUrlSigner.Sign($"/files/report?token={encodedJwt}", TestTtl, Key, timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider)
        };

        var result = await AuthenticateAsync(signedUrl, options, services =>
        {
            services.AddSingleton(CreateTokenValidationParameters());
        });

        Assert.True(result.Succeeded);
        Assert.Equal("jwt-user", result.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task AuthenticateAsync_Fails_ForJwtWithInvalidSignature()
    {
        var timeProvider = CreateTimeProvider();
        var jwt = CreateJwt(Encoding.UTF8.GetBytes("FEDCBA9876543210FEDCBA9876543210"));
        var encodedJwt = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(jwt));
        var signedUrl = TimedUrlSigner.Sign($"/files/report?token={encodedJwt}", TestTtl, Key, timeProvider);
        var options = new SignedUrlAuthenticationSchemeOptions
        {
            UrlSignerFactory = _ => TimedUrlSigner.Create(Key, timeProvider),
            TokenValidationParameters = CreateTokenValidationParameters()
        };

        var result = await AuthenticateAsync(signedUrl, options);

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
    }

    private static async Task<AuthenticateResult> AuthenticateAsync(string requestTarget, SignedUrlAuthenticationSchemeOptions options, Action<IServiceCollection>? configureServices = null)
    {
        var scheme = new AuthenticationScheme(SignedUrlHandler.SchemeName, SignedUrlHandler.SchemeName, typeof(SignedUrlHandler));
        var services = new ServiceCollection();
        configureServices?.Invoke(services);
        var context = new DefaultHttpContext
        {
            RequestServices = services.BuildServiceProvider()
        };

        var queryIndex = requestTarget.IndexOf('?');
        context.Request.Path = queryIndex >= 0 ? requestTarget[..queryIndex] : requestTarget;
        context.Request.QueryString = queryIndex >= 0 ? new QueryString(requestTarget[queryIndex..]) : QueryString.Empty;

        var handler = new SignedUrlHandler(
            new StaticOptionsMonitor<SignedUrlAuthenticationSchemeOptions>(options),
            NullLoggerFactory.Instance,
            UrlEncoder.Default);

        await handler.InitializeAsync(scheme, context);
        return await handler.AuthenticateAsync();
    }

    private static string CreateSignedUrl(string tokenValue, TimeProvider timeProvider)
    {
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(tokenValue));
        return TimedUrlSigner.Sign($"/files/report?token={encodedToken}", TestTtl, Key, timeProvider);
    }

    private static FakeTimeProvider CreateTimeProvider() => new(DateTimeOffset.Parse("2026-04-18T12:00:00Z"));

    private static string CreateJwt(byte[]? signingKey = null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = signingKey ?? JwtKey;
        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "jwt-user") }),
            Issuer = "UrlSigner.Tests",
            Audience = "UrlSigner.Tests",
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
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

    private sealed class StaticOptionsMonitor<TOptions> : IOptionsMonitor<TOptions>
    {
        private readonly TOptions options;

        public StaticOptionsMonitor(TOptions options)
        {
            this.options = options;
        }

        public TOptions CurrentValue => options;

        public TOptions Get(string? name) => options;

        public IDisposable? OnChange(Action<TOptions, string?> listener) => null;
    }

    private sealed class FakeTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset utcNow;

        public FakeTimeProvider(DateTimeOffset utcNow)
        {
            this.utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => utcNow;
    }
}


