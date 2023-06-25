using Microsoft.AspNetCore.Authentication;

namespace GoLive.UrlSigner.Authentication;

public static class SignedUrlExtensions
{
    public static AuthenticationBuilder AddSignedUrlAuth(this AuthenticationBuilder builder, Action<SignedUrlAuthenticationSchemeOptions> configureOptions = null)
    {
        return builder.AddScheme<SignedUrlAuthenticationSchemeOptions, SignedUrlHandler>(SignedUrlHandler.SchemeName, configureOptions);
    }
}