namespace GoLive.UrlSigner.Authentication;

public sealed class SignedUrlValidationOptions
{
    public Func<IServiceProvider, TimedUrlSigner>? UrlSignerFactory { get; set; }
}

