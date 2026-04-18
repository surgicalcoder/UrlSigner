using Microsoft.AspNetCore.Mvc;

namespace GoLive.UrlSigner.Authentication;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
public sealed class RequireSignedUrlAttribute : TypeFilterAttribute
{
    public RequireSignedUrlAttribute() : base(typeof(RequireSignedUrlFilter))
    {
        Order = int.MinValue;
    }
}

