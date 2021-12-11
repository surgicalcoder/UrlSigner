using System;
using System.Globalization;
using System.Net;

namespace GoLive.UrlSigner;
    public class TimedUrlSigner
    {
        public IUrlSigner Signer { get; }

        public TimedUrlSigner(IUrlSigner signer)
        {
            this.Signer = signer;
        }
        public Uri Sign(ReadOnlySpan<byte> key, Uri url, TimeSpan ttl)
        {
            return new Uri(this.Sign(key, url.ToString().AsSpan(), ttl));
        }

        public bool Verify(ReadOnlySpan<byte> key, Uri url) => this.Verify(key, url.ToString());

        public string Sign(ReadOnlySpan<byte> key, ReadOnlySpan<char> url, TimeSpan ttl)
        {
            if (url == null)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            var expTimeStamp = DateTime.UtcNow.Add(ttl);
            url = url.AppendParameter("exp", WebUtility.UrlEncode(expTimeStamp.ToString("O")));

            return this.Signer.Sign(key, url);
        }

        public bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<char> url)
        {
            if (url == null)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            var result = this.Signer.Verify(key, url);
             
            if (!result)
            {
                return false;
            }

            var unsignedUrl = url.RemoveLastParameter("sig", out var _);
            unsignedUrl.RemoveLastParameter("exp", out var expString);

            if (!DateTime.TryParse(WebUtility.UrlDecode(expString.ToString()),null, DateTimeStyles.AssumeUniversal, out var dt))
            {
                return false;
            }

            var res = dt.ToUniversalTime() > DateTime.UtcNow;
            return res;
        }
    }