using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;

namespace GoLive.UrlSigner.Authentication;

public static class SignedUrlValidationExtensions
{
    public static IServiceCollection AddSignedUrlValidation(this IServiceCollection services, Action<SignedUrlValidationOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<SignedUrlValidationOptions>();

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        return services;
    }

    public static IServiceCollection AddSignedUrlValidation(this IServiceCollection services, ReadOnlyMemory<byte> key, Action<SignedUrlValidationOptions>? configureOptions = null)
        => services.AddSignedUrlValidation<HMACSHA512>(key, configureOptions);

    public static IServiceCollection AddSignedUrlValidation<TAlg>(this IServiceCollection services, ReadOnlyMemory<byte> key, Action<SignedUrlValidationOptions>? configureOptions = null)
        where TAlg : KeyedHashAlgorithm, new()
    {
        ArgumentNullException.ThrowIfNull(services);

        if (key.IsEmpty)
        {
            throw new ArgumentException("Key must not be empty.", nameof(key));
        }

        return services.AddSignedUrlValidation(options =>
        {
            options.UrlSignerFactory = _ => TimedUrlSigner.Create<TAlg>(key);
            configureOptions?.Invoke(options);
        });
    }
}

