using System;

namespace GoLive.UrlSigner;

public static class Extensions
    {
        private static readonly char[] parameterCharArray = "?&;".ToCharArray();

        internal static ReadOnlySpan<char> RemoveLastParameter(this ReadOnlySpan<char> url, ReadOnlySpan<char> paramName, out ReadOnlySpan<char> paramValue)
        {
            if (url == null)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            if (paramName == null)
            {
                throw new ArgumentNullException(nameof(paramName));
            }

            if (paramName.IsEmpty || paramName.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(paramName));
            }

            var nameLength = paramName.Length;

            var baseUrl = url.RemoveFragment(out var fragment);

            var lastSeparatorIndex = baseUrl.LastIndexOfAny(parameterCharArray);

            if (lastSeparatorIndex < 1 || lastSeparatorIndex > url.Length - (nameLength + 3) || !url.Slice(lastSeparatorIndex + 1, nameLength + 1).Equals($"{paramName}=".AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                throw new FormatException("Invalid URL format");
            }

            paramValue = baseUrl[(lastSeparatorIndex + nameLength + 2)..];
            var shorterUrl = baseUrl[..lastSeparatorIndex];

            if (fragment.IsEmpty || fragment.IsWhiteSpace())
            {
                return shorterUrl;
            }
            else
            {
                return $"{shorterUrl}{fragment}".AsSpan(); // Todo need to make better
            }
        }

        internal static ReadOnlySpan<char> AppendParameter(this ReadOnlySpan<char> url, ReadOnlySpan<char> paramName, ReadOnlySpan<char> paramValue)
        {
            if (url == null)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            if (paramName == null)
            {
                throw new ArgumentNullException(nameof(paramName));
            }

            if (paramName.IsEmpty || paramName.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(paramName));
            }

            var baseUrl = RemoveFragment(url, out var fragment);
            var separator = baseUrl.Contains('?') ? "&" : "?";

            return $"{baseUrl}{separator}{paramName}={paramValue}{fragment}".AsSpan();
        }

        internal static ReadOnlySpan<char> RemoveFragment(this ReadOnlySpan<char> url) => RemoveFragment(url, out _);

        internal static ReadOnlySpan<char> RemoveFragment(this ReadOnlySpan<char> url, out ReadOnlySpan<char> fragment)
        {
            if (url == null)
            {
                throw new ArgumentNullException(nameof(url));
            }

            if (url.IsEmpty || url.IsWhiteSpace())
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(url));
            }

            var fragmentIndex = url.IndexOf('#');

            if (fragmentIndex < 0)
            {
                fragment = null;
                return url;
            }

            fragment = url[fragmentIndex..];

            return url[..fragmentIndex];
        }
    }