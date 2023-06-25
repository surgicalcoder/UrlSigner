using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace GoLive.UrlSigner.Authentication;

public class SignedUrlAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public Func<Memory<byte>, Task<ClaimsPrincipal>> GetPrinciple { get; set; }
}