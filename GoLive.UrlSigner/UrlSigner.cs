using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace GoLive.UrlSigner;
    public abstract class UrlSigner : IUrlSigner
    {
        protected abstract byte[] GetSignature(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);

        protected abstract bool VerifySignature(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig);
        
        public Uri Sign(ReadOnlySpan<byte> key, Uri url)
        {
            return new Uri(this.Sign(key, url.ToString()));
        }

        public bool Verify(ReadOnlySpan<byte> key, Uri url)
        {
            return this.Verify(key, url.ToString());
        }

        public virtual string Sign(ReadOnlySpan<byte> key, ReadOnlySpan<char> url)
        {
            if (url == null) throw new ArgumentNullException(nameof(url));

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            var baseUrl = url.RemoveFragment(out var fragment);

            var data = Encoding.UTF8.GetBytes(baseUrl.ToArray());

            var sigData = this.GetSignature(key, data);

            var sigString = WebEncoders.Base64UrlEncode(sigData);

            return string.Concat(baseUrl.AppendParameter("sig", sigString), fragment);
        }

        public virtual bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<char> url)
        {
            if (url == null) throw new ArgumentNullException(nameof(url));
            if (url.IsEmpty || url.IsWhiteSpace()) throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));

            try
            {
                var urlString = url.RemoveFragment().RemoveLastParameter("sig", out var sigString);
                var sigData = WebEncoders.Base64UrlDecode(sigString.ToString());

                var urlData = Encoding.UTF8.GetBytes(urlString.ToString());

                var res = this.VerifySignature(key, urlData, sigData);

                return res;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }