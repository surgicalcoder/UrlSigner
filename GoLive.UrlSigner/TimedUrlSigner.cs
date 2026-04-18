using System;
using System.Globalization;
using System.Security.Cryptography;

namespace GoLive.UrlSigner;
    public class TimedUrlSigner
    {
        public IUrlSigner Signer { get; }
        public TimeProvider TimeProvider { get; }

        public TimedUrlSigner(IUrlSigner signer, TimeProvider? timeProvider = null)
        {
            Signer = signer ?? throw new ArgumentNullException(nameof(signer));
            TimeProvider = timeProvider ?? TimeProvider.System;
        }

        public static TimedUrlSigner Create(ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            => Create<HMACSHA512>(key, timeProvider);

        public static TimedUrlSigner Create<TAlg>(ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            where TAlg : KeyedHashAlgorithm, new()
            => new(new HmacUrlSigner<TAlg>(key), timeProvider);

        public static string Sign(ReadOnlySpan<char> url, TimeSpan ttl, ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            => Create(key, timeProvider).Sign(url, ttl);

        public static string Sign<TAlg>(ReadOnlySpan<char> url, TimeSpan ttl, ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            where TAlg : KeyedHashAlgorithm, new()
            => Create<TAlg>(key, timeProvider).Sign(url, ttl);

        public static bool Verify(ReadOnlySpan<char> url, ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            => Create(key, timeProvider).Verify(url);

        public static bool Verify<TAlg>(ReadOnlySpan<char> url, ReadOnlyMemory<byte> key, TimeProvider? timeProvider = null)
            where TAlg : KeyedHashAlgorithm, new()
            => Create<TAlg>(key, timeProvider).Verify(url);

        public string Sign(string url, TimeSpan ttl)
        {
            ArgumentNullException.ThrowIfNull(url);
            return Sign(url.AsSpan(), ttl);
        }

        public string Sign(ReadOnlySpan<char> url, TimeSpan ttl)
        {
            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            if (ttl <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(ttl), ttl, "TTL must be greater than zero.");
            }

            if (url.ContainsParameter("exp"))
            {
                throw new ArgumentException("URL already contains the reserved 'exp' parameter.", nameof(url));
            }

            var expTimeStamp = TimeProvider.GetUtcNow().Add(ttl).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            var urlWithExpiration = url.AppendParameter("exp", expTimeStamp);

            return Signer.Sign(urlWithExpiration);
        }

        public bool Verify(string url)
        {
            ArgumentNullException.ThrowIfNull(url);
            return Verify(url.AsSpan());
        }

        public bool Verify(scoped ReadOnlySpan<char> url)
        {
            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            if (!Signer.Verify(url))
            {
                return false;
            }

            try
            {
                var unsignedUrl = url.RemoveParameter("sig", out _);
                unsignedUrl.AsSpan().RemoveParameter("exp", out var expString);

                if (!long.TryParse(expString, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dt))
                {
                    return false;
                }

                return DateTimeOffset.FromUnixTimeSeconds(dt) > TimeProvider.GetUtcNow();
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }