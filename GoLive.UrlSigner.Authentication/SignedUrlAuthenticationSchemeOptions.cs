using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace GoLive.UrlSigner.Authentication;

public class SignedUrlAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask<ClaimsPrincipal?>>? GetPrincipal { get; set; }

    public Func<IServiceProvider, TimedUrlSigner>? UrlSignerFactory { get; set; }

    public TokenValidationParameters? TokenValidationParameters { get; set; }
}