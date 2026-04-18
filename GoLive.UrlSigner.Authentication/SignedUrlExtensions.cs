using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;

namespace GoLive.UrlSigner.Authentication;

public static class SignedUrlExtensions
{
    public static AuthenticationBuilder AddSignedUrlAuthentication(this AuthenticationBuilder builder, Action<SignedUrlAuthenticationSchemeOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddScheme<SignedUrlAuthenticationSchemeOptions, SignedUrlHandler>(SignedUrlHandler.SchemeName, configureOptions);
    }

    public static AuthenticationBuilder AddSignedUrlAuthentication(this AuthenticationBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlAuthenticationSchemeOptions>? configureOptions = null)
        => builder.AddSignedUrlAuthentication<HMACSHA512>(key, configureOptions);

    public static AuthenticationBuilder AddSignedUrlAuthentication<TAlg>(this AuthenticationBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlAuthenticationSchemeOptions>? configureOptions = null)
        where TAlg : KeyedHashAlgorithm, new()
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (key.IsEmpty)
        {
            throw new ArgumentException("Key must not be empty.", nameof(key));
        }

        return builder.AddSignedUrlAuthentication(options =>
        {
            options.UrlSignerFactory = _ => TimedUrlSigner.Create<TAlg>(key);
            configureOptions?.Invoke(options);
        });
    }

    [Obsolete("Use AddSignedUrlAuthentication instead.")]
    public static AuthenticationBuilder AddSignedUrlAuth(this AuthenticationBuilder builder, Action<SignedUrlAuthenticationSchemeOptions>? configureOptions = null)
        => builder.AddSignedUrlAuthentication(configureOptions);

    [Obsolete("Use AddSignedUrlAuthentication(builder, key, ...) instead.")]
    public static AuthenticationBuilder AddSignedUrlAuth(this AuthenticationBuilder builder, ReadOnlyMemory<byte> key, Action<SignedUrlAuthenticationSchemeOptions>? configureOptions = null)
        => builder.AddSignedUrlAuthentication(key, configureOptions);
}