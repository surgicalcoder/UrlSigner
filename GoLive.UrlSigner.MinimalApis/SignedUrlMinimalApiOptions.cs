using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace GoLive.UrlSigner.MinimalApis;

public sealed class SignedUrlMinimalApiOptions
{
    public Func<IServiceProvider, TimedUrlSigner>? UrlSignerFactory { get; set; }

    public Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<ClaimsPrincipal?>>? GetPrincipal { get; set; }

    public TokenValidationParameters? TokenValidationParameters { get; set; }
}

