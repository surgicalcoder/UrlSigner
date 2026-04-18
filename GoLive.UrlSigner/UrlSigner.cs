using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace GoLive.UrlSigner;
    public abstract class UrlSigner : IUrlSigner
    {
        protected UrlSigner(ReadOnlyMemory<byte> key)
        {
            if (key.IsEmpty)
            {
                throw new ArgumentException("Key must not be empty.", nameof(key));
            }

            Key = key.ToArray();
        }

        protected abstract byte[] GetSignature(ReadOnlySpan<byte> data);

        protected abstract bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig);

        public string Sign(string url)
        {
            ArgumentNullException.ThrowIfNull(url);
            return Sign(url.AsSpan());
        }

        public string Sign(ReadOnlySpan<char> url)
        {
            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            if (url.ContainsParameter("sig"))
            {
                throw new ArgumentException("URL already contains the reserved 'sig' parameter.", nameof(url));
            }

            var baseUrl = url.RemoveFragment(out var fragment);
            var data = Encoding.UTF8.GetBytes(baseUrl);

            var sigData = GetSignature(data);

            var sigString = WebEncoders.Base64UrlEncode(sigData);

            return string.Concat(baseUrl.AsSpan().AppendParameter("sig", sigString), fragment);
        }

        public bool Verify(string url)
        {
            ArgumentNullException.ThrowIfNull(url);
            return Verify(url.AsSpan());
        }

        public bool Verify(ReadOnlySpan<char> url)
        {
            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            try
            {
                var urlString = url.RemoveFragment().AsSpan().RemoveParameter("sig", out var sigString);
                var sigData = WebEncoders.Base64UrlDecode(sigString);
                var urlData = Encoding.UTF8.GetBytes(urlString);
                return VerifySignature(urlData, sigData);
            }
            catch (Exception)
            {
                return false;
            }
        }

        protected ReadOnlyMemory<byte> Key { get; }
    }