using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GoLive.UrlSigner.Authentication;

public sealed class RequireSignedUrlFilter : IAsyncAuthorizationFilter
{
    private readonly SignedUrlValidationOptions options;

    public RequireSignedUrlFilter(IOptions<SignedUrlValidationOptions> options)
    {
        this.options = options.Value;
    }

    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var request = context.HttpContext.Request;

        if (!TryGetSingleQueryValue(request, "sig", out _) || !TryGetSingleQueryValue(request, "exp", out _))
        {
            context.Result = new UnauthorizedResult();
            return Task.CompletedTask;
        }

        var signer = options.UrlSignerFactory?.Invoke(context.HttpContext.RequestServices)
                     ?? context.HttpContext.RequestServices.GetService<TimedUrlSigner>();

        if (signer is null)
        {
            context.Result = new UnauthorizedResult();
            return Task.CompletedTask;
        }

        var requestTarget = string.Concat(
            request.PathBase.ToUriComponent(),
            request.Path.ToUriComponent(),
            request.QueryString.ToUriComponent());

        if (!signer.Verify(requestTarget))
        {
            context.Result = new UnauthorizedResult();
        }

        return Task.CompletedTask;
    }

    private static bool TryGetSingleQueryValue(HttpRequest request, string key, out string value)
    {
        if (!request.Query.TryGetValue(key, out var values) || values.Count == 0)
        {
            value = string.Empty;
            return false;
        }

        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
        {
            value = string.Empty;
            return false;
        }

        value = values[0] ?? string.Empty;
        return true;
    }
}


