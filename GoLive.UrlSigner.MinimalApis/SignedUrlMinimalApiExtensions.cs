using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace GoLive.UrlSigner.MinimalApis;

public static class SignedUrlMinimalApiExtensions
{
    public static RouteHandlerBuilder RequireSignedUrl(this RouteHandlerBuilder builder, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return AddSignedUrlFilter(builder, requiresToken: false, configureOptions);
    }

    public static RouteHandlerBuilder RequireSignedUrl(this RouteHandlerBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
        => builder.RequireSignedUrl<HMACSHA512>(key, configureOptions);

    public static RouteHandlerBuilder RequireSignedUrl<TAlg>(this RouteHandlerBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
        where TAlg : KeyedHashAlgorithm, new()
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("Key must not be empty.", nameof(key));
        }

        return builder.RequireSignedUrl(options =>
        {
            options.UrlSignerFactory = _ => TimedUrlSigner.Create<TAlg>(key);
            configureOptions?.Invoke(options);
        });
    }

    public static RouteHandlerBuilder RequireSignedUrlToken(this RouteHandlerBuilder builder, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return AddSignedUrlFilter(builder, requiresToken: true, configureOptions);
    }

    public static RouteHandlerBuilder RequireSignedUrlToken(this RouteHandlerBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
        => builder.RequireSignedUrlToken<HMACSHA512>(key, configureOptions);

    public static RouteHandlerBuilder RequireSignedUrlToken<TAlg>(this RouteHandlerBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlMinimalApiOptions>? configureOptions = null)
        where TAlg : KeyedHashAlgorithm, new()
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("Key must not be empty.", nameof(key));
        }

        return builder.RequireSignedUrlToken(options =>
        {
            options.UrlSignerFactory = _ => TimedUrlSigner.Create<TAlg>(key);
            configureOptions?.Invoke(options);
        });
    }

    private static RouteHandlerBuilder AddSignedUrlFilter(RouteHandlerBuilder builder, bool requiresToken, Action<SignedUrlMinimalApiOptions>? configureOptions)
    {
        return builder.AddEndpointFilterFactory((factoryContext, next) => async invocationContext =>
        {
            var httpContext = invocationContext.HttpContext;
            var options = new SignedUrlMinimalApiOptions();
            configureOptions?.Invoke(options);

            if (!TryGetSingleQueryValue(httpContext.Request, "sig", out _))
            {
                return Results.Unauthorized();
            }

            if (!TryGetSingleQueryValue(httpContext.Request, "exp", out _))
            {
                return Results.Unauthorized();
            }

            string encodedToken = string.Empty;
            if (requiresToken && !TryGetSingleQueryValue(httpContext.Request, "token", out encodedToken))
            {
                return Results.Unauthorized();
            }

            var urlSigner = ResolveUrlSigner(httpContext, options);
            if (urlSigner is null)
            {
                return Results.Unauthorized();
            }

            var requestTarget = string.Concat(
                httpContext.Request.PathBase.ToUriComponent(),
                httpContext.Request.Path.ToUriComponent(),
                httpContext.Request.QueryString.ToUriComponent());

            if (!urlSigner.Verify(requestTarget))
            {
                return Results.Unauthorized();
            }

            if (requiresToken)
            {
                try
                {
                    var token = WebEncoders.Base64UrlDecode(encodedToken).AsMemory();
                    var principal = await ResolvePrincipalAsync(httpContext, options, token).ConfigureAwait(false);

                    if (principal is null)
                    {
                        return Results.Unauthorized();
                    }

                    httpContext.User = principal;
                }
                catch
                {
                    return Results.Unauthorized();
                }
            }

            return await next(invocationContext).ConfigureAwait(false);
        });
    }

    private static TimedUrlSigner? ResolveUrlSigner(HttpContext httpContext, SignedUrlMinimalApiOptions options)
    {
        if (options.UrlSignerFactory is not null)
        {
            return options.UrlSignerFactory(httpContext.RequestServices);
        }

        return httpContext.RequestServices.GetService<TimedUrlSigner>();
    }

    private static async ValueTask<ClaimsPrincipal?> ResolvePrincipalAsync(HttpContext httpContext, SignedUrlMinimalApiOptions options, ReadOnlyMemory<byte> token)
    {
        if (options.GetPrincipal is not null)
        {
            return await options.GetPrincipal(token, httpContext.RequestAborted).ConfigureAwait(false);
        }

        var validationParameters = options.TokenValidationParameters ?? httpContext.RequestServices.GetService<TokenValidationParameters>();
        if (validationParameters is null)
        {
            throw new InvalidOperationException("TokenValidationParameters must be configured when GetPrincipal is not supplied.");
        }

        var decoded = Encoding.UTF8.GetString(token.Span);
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.ValidateToken(decoded, validationParameters, out _);
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

        value = values[0]!;
        return true;
    }
}


