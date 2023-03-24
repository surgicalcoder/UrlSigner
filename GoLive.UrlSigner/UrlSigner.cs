using System;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace GoLive.UrlSigner;
    public abstract class UrlSigner : IUrlSigner
    {
        protected abstract byte[] GetSignature(ReadOnlySpan<byte> data);

        protected abstract bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig);

        public string Sign(ReadOnlySpan<char> url)
        {
            if (url == null || url.Length == 0)
            {
                throw new ArgumentNullException();
            }
            
            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            var baseUrl = url.RemoveFragment(out var fragment);

            var data = Encoding.UTF8.GetBytes(baseUrl.ToArray());

            var sigData = GetSignature(data);

            var sigString = WebEncoders.Base64UrlEncode(sigData);

            return string.Concat(baseUrl.AppendParameter("sig", sigString), fragment);
        }

        public bool Verify(ReadOnlySpan<char> url)
        {
            if (url == null || url.Length == 0)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            try
            {
                var urlString = url.RemoveFragment().RemoveLastParameter("sig", out var sigString);
                var sigData = WebEncoders.Base64UrlDecode(sigString.ToString());
                var urlData = Encoding.UTF8.GetBytes(urlString.ToString());
                var res = VerifySignature(urlData, sigData);
                return res;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public ReadOnlyMemory<byte> Key { protected get; set; }
    }